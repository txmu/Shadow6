import Init

namespace Shadow6.Messager

-- BEGIN GENERATED VERIFIED GUARDS
abbrev chat_peer_bound (local_name : String) (recipient : String) (peer : String) (sender : String) : Prop :=
  ((local_name = recipient) ∧ (peer = sender))

-- END GENERATED VERIFIED GUARDS

theorem admitted_chat_is_for_local_identity (local_name recipient peer sender : String)
    (h : chat_peer_bound local_name recipient peer sender) : local_name = recipient := h.1

theorem admitted_chat_has_pinned_peer (local_name recipient peer sender : String)
    (h : chat_peer_bound local_name recipient peer sender) : peer = sender := h.2

theorem other_recipient_rejected (local_name recipient peer sender : String)
    (h : local_name ≠ recipient) : ¬ chat_peer_bound local_name recipient peer sender := by
  simp [chat_peer_bound, h]

theorem other_sender_rejected (local_name recipient peer sender : String)
    (h : peer ≠ sender) : ¬ chat_peer_bound local_name recipient peer sender := by
  simp [chat_peer_bound, h]

theorem exact_conversation_admitted (local_name peer : String) : chat_peer_bound local_name local_name peer peer := by
  simp [chat_peer_bound]

end Shadow6.Messager
