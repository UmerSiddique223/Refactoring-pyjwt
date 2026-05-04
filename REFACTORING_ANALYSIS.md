# PyJWT Refactoring Analysis (Parts 2 & 3)

This document records the code smells found in the PyJWT codebase and the
plan used to fix them. Part 1 (api_jws / api_jwt / warnings extraction) is
already merged on commit `e8a58e2`. This pass covers Parts 2 and 3 from
`REFACTORING_PLAN.md`.

The framework used to label smells follows the lecture material the user
provided: CK metrics (WMC, LCOM, CBO, RFC), MOOD (CF), Lorenz–Kidd
(method size / parameter count), and the Fowler/Beck catalog of smells
(Duplicated Code, Long Method, Feature Envy, Middle Man, Primitive
Obsession, Shotgun Surgery, etc.).

---

## 1. Smells Found in `jwt/algorithms.py`

`algorithms.py` is ~1000 lines — five algorithm classes inheriting from
the abstract `Algorithm` base. The file is structurally sound (each
algorithm has a clear responsibility, so cohesion per class is fine), but
there is significant **duplicated code** across families.

### 1.1 Duplicated Code — JWK JSON parsing prologue

Every `from_jwk(jwk: str | JWKDict)` implementation begins with the
exact same try/except block:

```python
try:
    if isinstance(jwk, str):
        obj = json.loads(jwk)
    elif isinstance(jwk, dict):
        obj = jwk
    else:
        raise ValueError
except ValueError:
    raise InvalidKeyError("Key is not valid JSON") from None
```

Repeated four times: HMAC `from_jwk` (358–366), RSA `from_jwk`
(500–508), EC `from_jwk` (723–731), OKP `from_jwk` (967–975).

**Smell labels:** Duplicated Code, Shotgun Surgery (a fix to JSON
handling has to land in four places).
**Metric impact:** WMC and RFC inflated across the algorithm classes
without semantic justification.

**Fix:** Extract a module-level helper `_parse_jwk_json(jwk)` that owns
parse + error wrapping and returns the dict. The four sites collapse to
one call.

### 1.2 Duplicated Code — `kty` validation message

Every `from_jwk` method then checks the `kty` field with a near-identical
two-line pattern:

```python
if obj.get("kty") != "<EXPECTED>":
    raise InvalidKeyError("Not a <human readable> key")
```

This is the same shape, only the literal differs. Extracting a helper
isn't strictly necessary — the helper plus the call is roughly the same
LOC as the duplicated check — so this stays inline. Listed here so the
audit is honest.

### 1.3 Duplicated Code — JWS load/parse JSON helper does not exist but is used inline

Same story applies, separately, to `to_jwk`'s `if as_dict: return obj
else: return json.dumps(obj)` tail. It appears in four classes (HMAC
345–354, RSA 460–496, EC 678–719, OKP 919–961).

**Fix:** Extract `_to_jwk_output(obj, as_dict)` that does the
final-step branch.

### 1.4 Long Method — `ECAlgorithm.from_jwk`

Lines 722–793. ~70 lines. Drives:

- JSON parse,
- `kty` check,
- coordinate length check (a four-way `if/elif/elif/elif` block),
- public-numbers construction,
- private-numbers construction.

**Smell labels:** Long Method, Conditional Complexity (high cyclomatic
complexity from the curve dispatch).

**Fix:** Extract `_resolve_ec_curve_from_jwk(crv, x, y)` which returns
the `EllipticCurve` instance or raises. The remaining body of `from_jwk`
becomes ~30 lines and reads top-to-bottom.

### 1.5 Long Method — `ECAlgorithm.to_jwk`

Lines 678–719. 4-way dispatch on `key_obj.curve` to map to the JWK
`crv` string. Mirror image of 1.4. Same fix shape: extract
`_jwk_curve_name(curve)`.

### 1.6 Conditional Complexity — `RSAAlgorithm.from_jwk` private-key branch

Lines 513–558 do a multi-stage validation of the optional CRT
parameters (`p`, `q`, `dp`, `dq`, `qi`). The "all or none" check plus
the recover-prime-factors fallback push cyclomatic complexity above
what's reasonable for one method.

**Fix:** Extract `_rsa_private_numbers_from_jwk(obj, public_numbers)`.

### 1.7 Long parameter list / unused `**kwargs` — `OKPAlgorithm.__init__`

Line 845: `def __init__(self, **kwargs: Any) -> None: pass`. Accepts
arbitrary kwargs and ignores them. This is an instance of **Speculative
Generality** (Fowler) — kept for symmetry with the other algorithms'
`__init__(hash_alg)` signatures, but it accepts any caller mistake
silently.

**Fix:** Out of scope per the plan ("do not change Algorithm public
method signatures") but called out here.

### 1.8 No central key-type validator

`ECAlgorithm.prepare_key` (615) and `RSAAlgorithm.prepare_key` (421)
both do `isinstance(key, self._crypto_key_types)` followed by
`isinstance(key, (bytes, str))` followed by a try/except over PEM/SSH
loaders. The skeleton repeats. The refactoring plan flags this; in
practice, the bodies diverge enough (RSA branches on `b"ssh-rsa"`
prefix; EC branches on `b"ecdsa-sha2-"`; OKP branches on PEM header
substrings) that a pulled-up template method would have a wide
parameter surface and not save much. Decision: **leave as-is**, document
the duplication, prefer the smaller wins (1.1, 1.3, 1.4, 1.5, 1.6).

---

## 2. Smells Found in JWK / JWKS / utility code

### 2.1 Middle Man — `PyJWTSetWithTimestamp`

`api_jwk.py:179–188`. The class wraps a `PyJWKSet` and a timestamp,
exposing them through `get_jwk_set()` and `get_timestamp()`. It is used
exactly once, inside `JWKSetCache`, which then immediately pulls the
two values back out:

```python
self.jwk_set_with_timestamp.get_jwk_set()
self.jwk_set_with_timestamp.get_timestamp() + self.lifespan
```

**Smell labels:** Middle Man (forwards calls without adding logic),
Speculative Generality, low WMC class with no callers outside the
single cache.

**Fix:** Inline. `JWKSetCache` stores `(jwk_set, timestamp)` directly.
The class disappears.

### 2.2 Feature Envy — kid-lookup logic on `PyJWKClient`

`jwks_client.py:215–233`, `match_kid(signing_keys, kid)`, is a
static method on `PyJWKClient` that operates entirely on data owned by
`PyJWKSet`. The plan called this out: "move kid-lookup off
`PyJWKClient` onto `PyJWKSet`."

**Smell labels:** Feature Envy (the method uses no `self`), Improper
Method Placement.

**Fix:** Add `PyJWKSet.get_signing_key_by_kid(kid)` returning
`PyJWK | None`. `PyJWKClient.get_signing_key` calls into the set.
`PyJWKClient.match_kid` stays as a thin compatibility wrapper because
it is `@staticmethod` and could plausibly be in user code.

### 2.3 Long Method — `PyJWK.__init__`

`api_jwk.py:20–82`. ~60 lines. The bulk is the `kty`→algorithm
dispatch (lines 41–66), a long `if/elif` over `EC / RSA / oct / OKP`
with nested curve dispatch.

**Smell labels:** Long Method, Conditional Complexity.

**Fix:** Extract `_infer_algorithm_from_kty(jwk_data, kty)`. The
constructor body collapses to a linear sequence: read kty → resolve alg
→ check crypto availability → build algorithm + key.

### 2.4 Lazy Class candidate — `JWKSetCache`

The class is small and has clear cohesion (storage + expiration
check). It is **not** a Lazy Class — keep it. Listed here so the audit
is explicit.

### 2.5 `utils.py` audit

`bytes_to_number` and `number_to_bytes` are used only by
`der_to_raw_signature` and `raw_to_der_signature` in the same module.
They are private helpers and don't warrant extraction or deletion. No
change.

`force_bytes`, `base64url_encode`, `base64url_decode`,
`to_base64url_uint`, `from_base64url_uint`, `is_pem_format`,
`is_ssh_key` all have multiple call sites across `algorithms.py` /
`api_jws.py`. **Keep.**

### 2.6 Type-alias audit (`types.py`)

All five exports (`JWKDict`, `HashlibHash`, `SigOptions`, `Options`,
`FullOptions`) are referenced by `api_jwk.py`, `algorithms.py`,
`api_jws.py`, `api_jwt.py`. **No deletions.**

---

## 3. Plan of Implementation

Each numbered task below produces one logical edit. After each, the
full pytest suite must remain green.

### Part 2 — `algorithms.py`

1. Add module-level `_parse_jwk_json(jwk)` and `_to_jwk_output(obj,
   as_dict)`. Replace the four duplicated copies (HMAC, RSA, EC, OKP).
2. Extract `_resolve_ec_curve_from_jwk(crv, x_len)` from
   `ECAlgorithm.from_jwk`. Returns the `EllipticCurve` instance.
3. Extract `_jwk_curve_name(curve)` from `ECAlgorithm.to_jwk`.
4. Extract `_rsa_private_numbers_from_jwk(obj, public_numbers)` from
   `RSAAlgorithm.from_jwk`.

### Part 3 — JWK / JWKS

5. Inline `PyJWTSetWithTimestamp` into `JWKSetCache`. Delete the
   wrapper class. Update imports.
6. Add `PyJWKSet.get_signing_key_by_kid(kid)`. Have
   `PyJWKClient.get_signing_key` delegate to it. Keep `match_kid` as a
   thin shim around the new method to preserve the public static-method
   surface.
7. Extract `PyJWK._infer_algorithm_from_kty()` from `PyJWK.__init__`.

### Validation

After each task: `python -m pytest tests/ -q`. The 344-pass / 4-skip
baseline must hold.

### What is intentionally **not** done

- No new error-handling semantics.
- No public API changes (`encode`, `decode`, `PyJWK`, `PyJWKSet`,
  `PyJWKClient` signatures all unchanged).
- No deletion of `utils.py` helpers (they have multiple call sites).
- No deletion of `types.py` aliases.
- `OKPAlgorithm.__init__(**kwargs)` left alone — see 1.7.
- Per-algorithm `prepare_key` skeletons left alone — see 1.8.
- Algorithm `sign` / `verify` byte-for-byte identical — they hit
  `cryptography` directly and the existing test vectors prove the wire
  format.

---

## 4. Part 1 Re-Audit (smells the original Part 1 missed)

The first pass on Part 1 (commit `e8a58e2`) covered duplicated kwargs
warnings and split the long `encode` method, but a second-pass review
found five smells that were not addressed. Each is fixed in this
revision.

### 4.1 Duplicated Code — `PyJWS._load` segment decoding

`api_jws.py:305–326`. Three near-identical try/except blocks:

```python
try:
    header_data = base64url_decode(header_segment)
except (TypeError, binascii.Error) as err:
    raise DecodeError("Invalid header padding") from err
```

Only the variable name and the error label change ("header padding" /
"payload padding" / "crypto padding"). Same exception types, same
wrapping behaviour.

**Smell labels:** Duplicated Code, Shotgun Surgery (a fix to the catch
list lands in three places).
**Metric impact:** WMC of `_load` is inflated; cyclomatic complexity
is higher than it needs to be.

**Fix:** Extract a private helper `_decode_segment(segment, label) ->
bytes` that owns the try/except. Three call sites become one-liners.

### 4.2 Duplicated Code — time-claim int coercion

`api_jwt.py:458–501`, methods `_validate_iat`, `_validate_nbf`,
`_validate_exp`. Each begins with the same shape:

```python
try:
    claim_value = int(payload[claim])
except ValueError:
    raise <SomeError>("<some message>") from None
```

Then each method does a single comparison and raises a different
timing-related error.

**Smell labels:** Duplicated Code; weak hint of **Template Method**
opportunity (the int-coerce-then-compare structure repeats).
**Metric impact:** WMC inflated across three methods; the int-coerce
fix-up has to be made three times if (e.g.) `TypeError` ever has to
join `ValueError`.

**Fix:** Extract `_coerce_int_claim(payload, claim) -> int`. The
type-error class and message per claim are looked up from a small
class-level mapping. The three validators keep their per-claim
comparison logic — that's where they actually differ.

### 4.3 Side Effects on Parameters — `PyJWT._merge_options`

`api_jwt.py:75–88`. The defensive default-overrides for the
`verify_x` flags **mutate the caller's options dict**:

```python
if not options.get("verify_signature", True):
    options["verify_exp"] = options.get("verify_exp", False)
    options["verify_nbf"] = options.get("verify_nbf", False)
    ...
```

A user who passes the same `options` object to two `decode()` calls
will see the first call's writes leak into the second. The comment
labels this "defensive" — the implementation is the opposite.

**Smell labels:** Side Effects on Parameters (a Beck/Fowler smell,
sometimes filed as Mysterious Behaviour). This is genuinely a **bug**,
not just a smell.

**Fix:** Compute the unverified-defaults overlay as a local dict,
and merge in order `self.options << defaults_when_unverified <<
options`. Caller's dict is no longer touched. Behaviour is identical.

### 4.4 Long Method / Mixed Concerns — `PyJWT.decode_complete`

`api_jwt.py:181–282`. The deprecated `verify` kwarg's mismatch
warning is 8 lines of legacy-handling sitting in the middle of the
real decode flow:

```python
if verify is not None and verify != verify_signature:
    warnings.warn(
        "The `verify` argument to `decode` does nothing in PyJWT 2.0...",
        category=DeprecationWarning,
        stacklevel=2,
    )
```

Same shape as the `RemovedInPyjwt3Warning` block that Part 1 already
extracted. Should have been pulled out at the same time.

**Smell labels:** Long Method, Mixed Concerns (legacy-API handling
mixed with the primary algorithm).

**Fix:** Extract `_warn_legacy_verify_mismatch(verify,
verify_signature)` as a static helper. `stacklevel=3` so the warning
still points at the original caller.

### 4.5 Replace Loop with Pipeline — `PyJWS.__init__`

`api_jws.py:41–49`:

```python
self._algorithms = get_default_algorithms()
self._valid_algs = (
    set(algorithms) if algorithms is not None else set(self._algorithms)
)
for key in list(self._algorithms.keys()):
    if key not in self._valid_algs:
        del self._algorithms[key]
```

Build a fresh dict, then loop deleting entries. A dict comprehension
says the same thing in one line and avoids the `list(...)` snapshot.

**Smell labels:** minor — Replace Loop with Pipeline (Fowler).

**Fix:** Replace the loop with a comprehension over the default
algorithms keyed by `_valid_algs`.

### Out of scope for the re-audit

- `PyJWT._validate_aud` (~50 lines, strict + non-strict modes). The
  branches share input-validation but their bodies are genuinely
  different operations. Splitting would create two private methods
  that are each only called from this one site — moves complexity
  rather than reducing it. Left as-is.
- `_validate_kid` / `_validate_crit` — Part 1 plan explicitly said
  not to inline these. Honored.
- `decode_complete` overall structure (load → validate → verify) —
  the body is linear and reads cleanly once 4.4 is extracted.
- `_supported_crit` class attribute placement — currently mid-class,
  could be top-of-class. Cosmetic, skipped.

