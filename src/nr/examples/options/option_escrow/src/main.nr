use aztec::macros::aztec;
mod types;

/// American/European option escrow gated by zkTLS-attested Binance klines.
/// Each option lives in its own private `Escrow` instance (from
/// `aztec-standards`) addressed by `(secret_key, this_address)`. Per-option
/// state is three notes (Core, Offer, Proposal) keyed by escrow address;
/// Proposal note presence = "pending", absence = "active".
///
/// Lifecycle: `offer` -> (`subscribe` | `cancel`);
/// subscribed -> (`exercise` | `reclaim`). See the examples README
/// for the full flow and trust model.
#[aztec]
pub contract OptionEscrowLogic {
    use crate::types::{
        core_note::EscrowCoreNote,
        offer_note::EscrowOfferNote,
        option_terms::{CoreTerms, OfferTerms},
        proposal_note::EscrowProposalNote,
    };

    use aztec::{
        context::PrivateContext,
        macros::{functions::{external, initializer, view}, storage::storage},
        messages::message_delivery::MessageDelivery,
        note::note_getter_options::NoteGetterOptions,
        protocol::{address::AztecAddress, hash::poseidon2_hash, traits::ToField},
        state_vars::{Owned, PrivateSet, PublicImmutable},
        utils::comparison::Comparator,
    };
    use escrow_standard::library::logic::{_get_escrow, _share_escrow, _withdraw};
    use klines_oracle::{
        KlinesOracle,
        constants::{
            MAX_COND_LEN, MAX_CONTENT_LEN, MAX_DATA_LEN, MAX_HMB_LEN, MAX_PARAMS_LEN,
            MAX_QUERY_PREFIX_LEN, MAX_RR_LEN, MAX_URL_LEN, NUM_RESPONSE_RESOLVE,
        },
        types::{envelope::Envelope as OracleEnvelope, klines_candle::KlinesCandle},
    };
    use public_checks_contract::utils::privately_check_timestamp;
    use token::Token;

    global ROLE_BUYER: u8 = 0;
    global ROLE_SELLER: u8 = 1;

    /// 1-minute candles. Ms for candle math, seconds for block.timestamp.
    global CANDLE_INTERVAL_MS: u64 = 60_000;
    global CANDLE_INTERVAL_S: u64 = 60;
    /// Window around `deadline` in which a European candle may settle.
    global SETTLEMENT_WINDOW_S: u64 = 5 * 60;
    /// Max age of an American-exercise candle relative to `now`.
    global RECENCY_WINDOW_S: u64 = 10 * 60;
    /// European late-exercise grace after `deadline`.
    global LATE_EXERCISE_GRACE_S: u64 = 24 * 60 * 60;

    #[storage]
    struct Storage<Context> {
        escrow_class_id: PublicImmutable<Field, Context>,
        oracle_address: PublicImmutable<AztecAddress, Context>,
        // Per-option notes keyed by escrow address. Proposal existence = pending.
        core_notes: Owned<PrivateSet<EscrowCoreNote, Context>, Context>,
        offer_notes: Owned<PrivateSet<EscrowOfferNote, Context>, Context>,
        proposal_notes: Owned<PrivateSet<EscrowProposalNote, Context>, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(escrow_class_id: Field, oracle_address: AztecAddress) {
        self.storage.escrow_class_id.initialize(escrow_class_id);
        self.storage.oracle_address.initialize(oracle_address);
    }

    /// Initiate an option. Either side may propose; their deposit flows into
    /// the escrow. Writes Core+Offer+Proposal notes. Requires an authwit for
    /// the deposit transfer.
    #[external("private")]
    fn offer(
        my_role: u8,
        counterparty: AztecAddress,
        core: CoreTerms,
        offer_terms: OfferTerms,
        secret_key: Field,
        deposit_nonce: Field,
    ) {
        assert((my_role == ROLE_BUYER) | (my_role == ROLE_SELLER), "invalid role");

        // Short alias for the offer terms / offer note throughout the body.
        let terms = offer_terms;
        let me = self.msg_sender();
        let (buyer, seller) = if my_role == ROLE_BUYER {
            (me, counterparty)
        } else {
            (counterparty, me)
        };

        let escrow = _get_escrow(
            self.context,
            self.storage.escrow_class_id.read(),
            secret_key,
        );
        _share_escrow(self.context, buyer, escrow, secret_key);
        _share_escrow(self.context, seller, escrow, secret_key);

        // Pull proposer's deposit. Buyer deposits premium (quote_token);
        // seller deposits collateral (base_token for call, quote_token for put).
        if my_role == ROLE_BUYER {
            self.call(Token::at(core.quote_token).transfer_private_to_private(
                me,
                escrow,
                terms.premium_amount,
                deposit_nonce,
            ));
        } else if terms.is_call {
            self.call(Token::at(core.base_token).transfer_private_to_private(
                me,
                escrow,
                core.base_amount,
                deposit_nonce,
            ));
        } else {
            self.call(Token::at(core.quote_token).transfer_private_to_private(
                me,
                escrow,
                core.quote_amount,
                deposit_nonce,
            ));
        }

        let core_note = EscrowCoreNote {
            buyer,
            seller,
            deadline: core.deadline,
            base_token: core.base_token,
            base_amount: core.base_amount,
            quote_token: core.quote_token,
            quote_amount: core.quote_amount,
        };
        self.storage.core_notes.at(escrow).insert(core_note).deliver(
            MessageDelivery.ONCHAIN_CONSTRAINED,
        );

        let offer_note = EscrowOfferNote {
            premium_amount: terms.premium_amount,
            strike: terms.strike,
            is_call: terms.is_call,
            is_american: terms.is_american,
            pinned_query_prefix_hash: terms.pinned_query_prefix_hash,
        };
        self.storage.offer_notes.at(escrow).insert(offer_note).deliver(
            MessageDelivery.ONCHAIN_CONSTRAINED,
        );

        let proposal_note = EscrowProposalNote {
            proposer: me,
            missing_side: if my_role == ROLE_BUYER {
                ROLE_SELLER
            } else {
                ROLE_BUYER
            },
        };
        self.storage.proposal_notes.at(escrow).insert(proposal_note).deliver(
            MessageDelivery.ONCHAIN_CONSTRAINED,
        );

        // Nullify the escrow address so the same secret_key can't be reused.
        let nullifier = std::hash::pedersen_hash([escrow.to_field()]);
        self.context.push_nullifier(nullifier);
    }

    /// Counterparty completes the option. Pulls the missing side's deposit
    /// into the escrow, releases the premium to the seller, nullifies the
    /// Proposal note (option becomes active).
    #[external("private")]
    fn subscribe(escrow: AztecAddress, deposit_nonce: Field) {
        let me = self.msg_sender();
        let core = _find_core_note(self.storage, escrow);
        let terms = _find_offer_note(self.storage, escrow);
        let proposal = _consume_proposal_note(self.storage, escrow);

        if proposal.missing_side == ROLE_BUYER {
            assert_eq(me, core.buyer, "caller must be buyer");
        } else {
            assert_eq(me, core.seller, "caller must be seller");
        }

        // Pull missing side's deposit (premium for buyer, collateral for seller).
        if proposal.missing_side == ROLE_BUYER {
            self.call(Token::at(core.quote_token).transfer_private_to_private(
                me,
                escrow,
                terms.premium_amount,
                deposit_nonce,
            ));
        } else if terms.is_call {
            self.call(Token::at(core.base_token).transfer_private_to_private(
                me,
                escrow,
                core.base_amount,
                deposit_nonce,
            ));
        } else {
            self.call(Token::at(core.quote_token).transfer_private_to_private(
                me,
                escrow,
                core.quote_amount,
                deposit_nonce,
            ));
        }

        // Release premium from escrow to seller.
        _withdraw(
            self.context,
            escrow,
            core.seller,
            core.quote_token,
            terms.premium_amount,
        );
    }

    /// Buyer exercises an active option. Calls the oracle for a verified
    /// candle, checks 1-min interval + timing window + strike, then routes
    /// settlement (buyer->seller) and the locked collateral (escrow->buyer).
    #[external("private")]
    fn exercise(
        escrow: AztecAddress,
        // zkTLS witness, forwarded to the oracle.
        signature: [u8; 64],
        envelope: OracleEnvelope<MAX_URL_LEN, MAX_HMB_LEN, NUM_RESPONSE_RESOLVE, MAX_RR_LEN, MAX_DATA_LEN, MAX_COND_LEN, MAX_PARAMS_LEN>,
        contents: [BoundedVec<u8, MAX_CONTENT_LEN>; NUM_RESPONSE_RESOLVE],
        data_hash_offsets: [u32; NUM_RESPONSE_RESOLVE],
        query_prefix: BoundedVec<u8, MAX_QUERY_PREFIX_LEN>,
        settlement_nonce: Field,
    ) {
        let me = self.msg_sender();
        let core = _find_core_note(self.storage, escrow);
        let terms = _find_offer_note(self.storage, escrow);

        assert_eq(me, core.buyer, "only buyer can exercise");

        // Option must be active (Proposal note nullified at subscribe).
        let opts = NoteGetterOptions::new().set_limit(1);
        let proposal_notes = self.storage.proposal_notes.at(escrow).get_notes(opts);
        assert(proposal_notes.len() == 0, "option not yet active");

        // Buyer's claimed query_prefix must match what was pinned at offer time.
        let query_prefix_hash = _hash_query_prefix(query_prefix);
        assert_eq(query_prefix_hash, terms.pinned_query_prefix_hash, "query_prefix mismatch");

        // Oracle call: verifies attestation, returns the parsed candle.
        let candle: KlinesCandle = KlinesOracle::at(self.storage.oracle_address.read())
            .verify_klines_attestation(
                signature,
                envelope,
                contents,
                data_hash_offsets,
                query_prefix,
            )
            .call(self.context);

        // 1-minute candle (oracle is interval-agnostic).
        assert_eq(
            candle.close_time - candle.open_time + 1,
            CANDLE_INTERVAL_MS,
            "candle is not 1-minute interval",
        );

        // `open_time` is ms at a minute boundary -> /1000 is exact seconds.
        let candle_open_s = candle.open_time / 1000;

        if terms.is_american {
            // Strictly before deadline; candle must have finalized AND be recent.
            privately_check_timestamp(Comparator.LTE, core.deadline, self.context);
            privately_check_timestamp(
                Comparator.GTE,
                candle_open_s + CANDLE_INTERVAL_S,
                self.context,
            );
            privately_check_timestamp(
                Comparator.LTE,
                candle_open_s + RECENCY_WINDOW_S,
                self.context,
            );
        } else {
            // European: within [deadline, deadline + grace], candle near deadline.
            privately_check_timestamp(Comparator.GTE, core.deadline, self.context);
            privately_check_timestamp(
                Comparator.LTE,
                core.deadline + LATE_EXERCISE_GRACE_S,
                self.context,
            );
            assert(candle_open_s + CANDLE_INTERVAL_S >= core.deadline, "candle before deadline");
            assert(
                candle_open_s <= core.deadline + SETTLEMENT_WINDOW_S,
                "candle too far past deadline",
            );
        }

        // Strike check on midpoint.
        let price = (candle.open_price + candle.close_price) / 2;
        if terms.is_call {
            assert(price >= terms.strike, "call not in the money");
        } else {
            assert(price <= terms.strike, "put not in the money");
        }

        // Movements: call -> buyer pays quote, gets base. Put -> reversed.
        if terms.is_call {
            self.call(Token::at(core.quote_token).transfer_private_to_private(
                core.buyer,
                core.seller,
                core.quote_amount,
                settlement_nonce,
            ));
            _withdraw(
                self.context,
                escrow,
                core.buyer,
                core.base_token,
                core.base_amount,
            );
        } else {
            self.call(Token::at(core.base_token).transfer_private_to_private(
                core.buyer,
                core.seller,
                core.base_amount,
                settlement_nonce,
            ));
            _withdraw(
                self.context,
                escrow,
                core.buyer,
                core.quote_token,
                core.quote_amount,
            );
        }
    }

    /// Cancel a pending option. Proposer reclaims their deposit. Reverts if
    /// the Proposal note no longer exists (option already subscribed).
    #[external("private")]
    fn cancel(escrow: AztecAddress) {
        let core = _find_core_note(self.storage, escrow);
        let terms = _find_offer_note(self.storage, escrow);
        let proposal = _consume_proposal_note(self.storage, escrow);

        // Proposer's side is the OPPOSITE of `missing_side`.
        if proposal.missing_side == ROLE_BUYER {
            // Seller was proposer -> collateral.
            if terms.is_call {
                _withdraw(
                    self.context,
                    escrow,
                    proposal.proposer,
                    core.base_token,
                    core.base_amount,
                );
            } else {
                _withdraw(
                    self.context,
                    escrow,
                    proposal.proposer,
                    core.quote_token,
                    core.quote_amount,
                );
            }
        } else {
            // Buyer was proposer -> premium.
            _withdraw(
                self.context,
                escrow,
                proposal.proposer,
                core.quote_token,
                terms.premium_amount,
            );
        }
    }

    /// Reclaim collateral on a subscribed-but-unexercised option past its
    /// flavor cutoff (American: `now > deadline`; European:
    /// `now > deadline + grace`). Reverts if option is still pending.
    #[external("private")]
    fn reclaim(escrow: AztecAddress) {
        let core = _find_core_note(self.storage, escrow);
        let terms = _find_offer_note(self.storage, escrow);

        // Must not be pending.
        let opts = NoteGetterOptions::new().set_limit(1);
        let proposal_notes = self.storage.proposal_notes.at(escrow).get_notes(opts);
        assert(proposal_notes.len() == 0, "option still pending; use cancel");

        if terms.is_american {
            privately_check_timestamp(Comparator.GT, core.deadline, self.context);
        } else {
            privately_check_timestamp(
                Comparator.GT,
                core.deadline + LATE_EXERCISE_GRACE_S,
                self.context,
            );
        }

        if terms.is_call {
            _withdraw(
                self.context,
                escrow,
                core.seller,
                core.base_token,
                core.base_amount,
            );
        } else {
            _withdraw(
                self.context,
                escrow,
                core.seller,
                core.quote_token,
                core.quote_amount,
            );
        }
    }

    #[external("private")]
    #[view]
    fn get_escrow(secret_key: Field) -> pub AztecAddress {
        _get_escrow(
            self.context,
            self.storage.escrow_class_id.read(),
            secret_key,
        )
    }

    #[contract_library_method]
    fn _find_core_note(
        storage: Storage<&mut PrivateContext>,
        escrow: AztecAddress,
    ) -> EscrowCoreNote {
        let opts = NoteGetterOptions::new().set_limit(1);
        let notes = storage.core_notes.at(escrow).get_notes(opts);
        assert(notes.len() == 1, "core note not found");
        notes.get_unchecked(0).note
    }

    #[contract_library_method]
    fn _find_offer_note(
        storage: Storage<&mut PrivateContext>,
        escrow: AztecAddress,
    ) -> EscrowOfferNote {
        let opts = NoteGetterOptions::new().set_limit(1);
        let notes = storage.offer_notes.at(escrow).get_notes(opts);
        assert(notes.len() == 1, "offer note not found");
        notes.get_unchecked(0).note
    }

    #[contract_library_method]
    fn _consume_proposal_note(
        storage: Storage<&mut PrivateContext>,
        escrow: AztecAddress,
    ) -> EscrowProposalNote {
        let opts = NoteGetterOptions::new().set_limit(1);
        let notes = storage.proposal_notes.at(escrow).get_notes(opts);
        assert(notes.len() == 1, "proposal note not found (already subscribed?)");
        let retrieved = notes.get_unchecked(0);
        storage.proposal_notes.at(escrow).remove(retrieved);
        retrieved.note
    }

    /// Poseidon2-hash `query_prefix` zero-padded to MAX_QUERY_PREFIX_LEN.
    /// Off-chain hashers must apply the same padding.
    #[contract_library_method]
    fn _hash_query_prefix(query_prefix: BoundedVec<u8, MAX_QUERY_PREFIX_LEN>) -> Field {
        let mut inputs: [Field; MAX_QUERY_PREFIX_LEN] = [0; MAX_QUERY_PREFIX_LEN];
        for i in 0..MAX_QUERY_PREFIX_LEN {
            if i < query_prefix.len() {
                inputs[i] = query_prefix.storage()[i] as Field;
            }
        }
        poseidon2_hash(inputs)
    }
}
