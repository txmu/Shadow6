import Init

/-! Shared transport credit and capability models. Ada/SPARK and Idris dependent
type proofs remain separate native evidence; no C/Go/Rust/FFI equivalence claim. -/
namespace Shadow6.Contracts

structure Credits where
  capacity : Nat
  available : Nat
  outstanding : Nat
  deriving DecidableEq

def valid (s : Credits) : Prop := s.available + s.outstanding = s.capacity

def reserve (s : Credits) (amount : Nat) : Option Credits :=
  if amount ≤ s.available then
    some {s with available := s.available - amount, outstanding := s.outstanding + amount}
  else none

def acknowledge (s : Credits) (amount : Nat) : Option Credits :=
  if amount ≤ s.outstanding then
    some {s with available := s.available + amount, outstanding := s.outstanding - amount}
  else none

theorem reserve_conserves_credits (s next : Credits) (amount : Nat)
    (invariant : valid s) (accepted : reserve s amount = some next) : valid next := by
  unfold reserve at accepted
  split at accepted
  · cases accepted
    unfold valid at *
    simp only at *
    omega
  · cases accepted

theorem acknowledge_conserves_credits (s next : Credits) (amount : Nat)
    (invariant : valid s) (accepted : acknowledge s amount = some next) : valid next := by
  unfold acknowledge at accepted
  split at accepted
  · cases accepted
    unfold valid at *
    simp only at *
    omega
  · cases accepted

theorem cannot_overdraw (s : Credits) (amount : Nat) (h : s.available < amount) :
    reserve s amount = none := by
  simp [reserve, Nat.not_le.mpr h]

theorem cannot_invent_acknowledgements (s : Credits) (amount : Nat) (h : s.outstanding < amount) :
    acknowledge s amount = none := by
  simp [acknowledge, Nat.not_le.mpr h]

theorem available_bounded (s : Credits) (h : valid s) : s.available ≤ s.capacity := by
  unfold valid at h
  omega

theorem outstanding_bounded (s : Credits) (h : valid s) : s.outstanding ≤ s.capacity := by
  unfold valid at h
  omega

def frameAccepted (declared received limit : Nat) (authenticated : Bool) : Prop :=
  0 < declared ∧ declared = received ∧ received ≤ limit ∧ authenticated = true

theorem unauthenticated_frame_rejected (declared received limit : Nat) :
    ¬ frameAccepted declared received limit false := by
  intro h
  cases h.2.2.2

theorem partial_frame_never_released (declared received limit : Nat) (authenticated : Bool)
    (partialFrame : received < declared) : ¬ frameAccepted declared received limit authenticated := by
  intro h
  have equal := h.2.1
  omega

theorem oversized_frame_rejected (declared received limit : Nat) (authenticated : Bool)
    (oversized : limit < received) : ¬ frameAccepted declared received limit authenticated := by
  intro h
  have bounded := h.2.2.1
  omega

def capabilityAllowed (build grant policy domain : Bool) : Bool := build && grant && policy && domain

theorem disabled_build_never_grants (grant policy domain : Bool) :
    capabilityAllowed false grant policy domain = false := by
  simp [capabilityAllowed]

theorem missing_grant_never_grants (build policy domain : Bool) :
    capabilityAllowed build false policy domain = false := by
  simp [capabilityAllowed]

theorem denied_domain_never_grants (build grant policy : Bool) :
    capabilityAllowed build grant policy false = false := by
  simp [capabilityAllowed]

end Shadow6.Contracts
