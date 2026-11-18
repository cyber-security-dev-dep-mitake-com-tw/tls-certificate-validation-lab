"""
Lab-only number theory.

`generate` creates synthetic weak parameters at or below 512 bits.
`analyze` sees only public values and never returns factors.
`oracle` confirms a fixture the lab itself just created. It refuses
harvested origins and any modulus above 512 bits, and its response
does not echo primes or private exponents.
"""
module LabCrypto

using Random

export handle_generate, handle_analyze, handle_oracle
export roca_fingerprint, JSON

const MAX_GENERATE_BITS = 512
const MAX_ORACLE_BITS = 512
const MAX_GCD_BITS = 1024
const ROCA_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
)
const ROCA_MODULUS = prod(BigInt.(ROCA_PRIMES))
const PRIVATE_FIELDS = (
    "d", "p", "q", "dp", "dq", "phi", "private", "private_key",
    "factor", "factors", "iqmp", "dmp1", "dmq1",
)

include("json.jl")

function refuse(reason::AbstractString)
    Dict{String,Any}("ok" => false, "refused" => true, "error" => String(reason))
end

function ndigits2(n::BigInt)
    n <= 0 && return 0
    return ndigits(n, base=2)
end

function rand_below(span::BigInt)
    span <= 0 && error("empty span")
    bits = ndigits(span, base=2)
    nbytes = cld(bits, 8)
    while true
        raw = rand(UInt8, nbytes)
        r = parse(BigInt, bytes2hex(raw); base=16)
        r >>= (8 * nbytes - bits)
        if r < span
            return r
        end
    end
end

function rand_bits(bits::Int)
    nbytes = cld(bits, 8)
    raw = rand(UInt8, nbytes)
    extra = 8 * nbytes - bits
    if extra > 0
        raw[1] &= 0xff >> extra
    end
    raw[1] |= UInt8(1) << ((bits - 1) % 8)
    raw[end] |= 0x01
    return parse(BigInt, bytes2hex(raw); base=16)
end

function miller_rabin(n::BigInt; rounds::Int=8)
    if n == 2 || n == 3
        return true
    end
    if n < 2 || iseven(n)
        return false
    end
    d = n - 1
    s = 0
    while iseven(d)
        d >>= 1
        s += 1
    end
    for _ in 1:rounds
        a = BigInt(2) + rand_below(n - 3)
        x = powermod(a, d, n)
        if x == 1 || x == n - 1
            continue
        end
        witnessed = true
        for _ in 1:(s - 1)
            x = powermod(x, 2, n)
            if x == n - 1
                witnessed = false
                break
            end
        end
        if witnessed
            return false
        end
    end
    return true
end

function random_prime(bits::Int)
    for _ in 1:200000
        cand = rand_bits(bits)
        if cand > 2 && miller_rabin(cand)
            return cand
        end
    end
    error("prime search failed")
end

function next_prime(n::BigInt)
    cand = n < 2 ? BigInt(2) : (iseven(n) ? n + 1 : n + 2)
    while !miller_rabin(cand)
        cand += 2
    end
    return cand
end

"""Quadratic-residue fingerprint used by the lab's ROCA fixture.

The prime set is the primorial that still leaves room for a 256-bit prime.
This is a public marker, not Coppersmith's attack.
"""
function roca_fingerprint(n::BigInt)
    if n <= 2
        return false
    end
    for p in ROCA_PRIMES
        if mod(n, p) == 0
            continue
        end
        if powermod(n, (p - 1) ÷ 2, BigInt(p)) != 1
            return false
        end
    end
    return true
end

function random_roca_prime(bits::Int)
    m = ROCA_MODULUS
    if bits <= ndigits2(m) + 2
        error("bits too small for roca prime")
    end
    low = BigInt(1) << (bits - 1)
    high = (BigInt(1) << bits) - 1
    k_low = cld(low - 1, m)
    k_high = fld(high - 1, m)
    span = k_high - k_low
    span <= 0 && error("no roca residue in range")
    for _ in 1:40000
        k = k_low + rand_below(span + 1)
        cand = k * m + 1
        if isodd(cand) && ndigits2(cand) == bits && miller_rabin(cand)
            return cand
        end
    end
    error("roca prime search failed")
end

function key_record(n::BigInt, e::BigInt, d::BigInt, p::BigInt, q::BigInt)
    if p < q
        p, q = q, p
    end
    Dict{String,Any}(
        "n" => string(n),
        "e" => string(e),
        "d" => string(d),
        "p" => string(p),
        "q" => string(q),
    )
end

function rsa_from_primes(p::BigInt, q::BigInt, e::BigInt)
    if p == q
        q = next_prime(q + 2)
    end
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1
        return nothing
    end
    d = invmod(e, phi)
    return key_record(n, e, d, p, q)
end

function standard_key(bits::Int; e::BigInt=BigInt(65537))
    half = bits ÷ 2
    for _ in 1:32
        rec = rsa_from_primes(random_prime(half), random_prime(half), e)
        if rec !== nothing
            return rec
        end
    end
    error("unable to build rsa key")
end

function roca_key(bits::Int)
    half = bits ÷ 2
    for _ in 1:8
        rec = rsa_from_primes(random_roca_prime(half), random_roca_prime(half), BigInt(65537))
        if rec !== nothing && roca_fingerprint(parse(BigInt, rec["n"]))
            return rec
        end
    end
    error("unable to build roca fixture")
end

function shared_prime_keys(bits::Int)
    half = bits ÷ 2
    e = BigInt(65537)
    for _ in 1:32
        p = random_prime(half)
        a = rsa_from_primes(p, random_prime(half), e)
        b = rsa_from_primes(p, random_prime(half), e)
        if a === nothing || b === nothing
            continue
        end
        if a["n"] == b["n"]
            continue
        end
        return Any[a, b]
    end
    error("unable to build shared-prime fixtures")
end

function wiener_key(bits::Int)
    half = bits ÷ 2
    for _ in 1:32
        p = random_prime(half)
        q = random_prime(half)
        if p == q
            continue
        end
        n = p * q
        phi = (p - 1) * (q - 1)
        limit = isqrt(isqrt(n))
        limit > BigInt(16) || continue
        d = BigInt(0)
        for _ in 1:4000
            cand = BigInt(3) + rand_below(min(limit - 3, BigInt(2)^32))
            if cand < limit && gcd(cand, phi) == 1
                d = cand
                break
            end
        end
        if d == 0
            continue
        end
        e = invmod(d, phi)
        return key_record(n, e, d, p, q)
    end
    error("unable to build wiener fixture")
end

function fermat_key(bits::Int)
    half = bits ÷ 2
    p = random_prime(half)
    q = next_prime(p + BigInt(2)^16)
    rec = rsa_from_primes(p, q, BigInt(65537))
    rec === nothing && error("unable to build fermat fixture")
    return rec
end

function as_int(value)
    if value isa Integer
        return Int(value)
    elseif value isa AbstractString
        return parse(Int, value)
    end
    error("bad integer")
end

function has_private_field(req)
    for key in PRIVATE_FIELDS
        if haskey(req, key)
            return true
        end
    end
    return false
end

function handle_generate(req)
    if !(req isa AbstractDict)
        return refuse("bad_request")
    end
    if get(req, "op", "generate") == "factor" || haskey(req, "n") || haskey(req, "modulus")
        return refuse("no_factor")
    end
    origin = string(get(req, "origin", ""))
    profile = string(get(req, "profile", ""))
    bits = try
        as_int(get(req, "bits", 0))
    catch
        return refuse("bits")
    end
    if origin != "synthetic" || bits < 256 || bits > MAX_GENERATE_BITS || isodd(bits)
        return refuse("origin_or_size")
    end
    keys = try
        if profile == "weak_rsa"
            Any[standard_key(bits)]
        elseif profile == "shared_prime"
            shared_prime_keys(bits)
        elseif profile == "roca"
            Any[roca_key(bits)]
        elseif profile == "wiener"
            Any[wiener_key(bits)]
        elseif profile == "fermat"
            Any[fermat_key(bits)]
        else
            return refuse("profile")
        end
    catch err
        return refuse("generate_failed: " * sprint(showerror, err))
    end
    for key in keys
        n = parse(BigInt, key["n"])
        if ndigits2(n) > MAX_GENERATE_BITS
            return refuse("generated_too_large")
        end
    end
    return Dict{String,Any}("ok" => true, "profile" => profile, "keys" => keys)
end

function public_reasons(n::BigInt, e::BigInt, sig_alg::AbstractString)
    reasons = String[]
    bits = ndigits2(n)
    if 0 < bits < 2048
        push!(reasons, "WEAK_KEY")
    end
    if roca_fingerprint(n)
        push!(reasons, "ROCA_FINGERPRINT")
    end
    if ndigits2(e) * 2 > bits
        push!(reasons, "STRUCTURAL_WEAKNESS")
    end
    lowered = lowercase(String(sig_alg))
    if occursin("sha1", lowered) || occursin("md5", lowered)
        push!(reasons, "WEAK_SIGNATURE")
    end
    return reasons, bits
end

function batch_pairs(moduli)
    eligible = Tuple{Int,BigInt}[]
    for (index, item) in enumerate(moduli)
        n = parse(BigInt, string(item))
        if 1 < ndigits2(n) <= MAX_GCD_BITS
            push!(eligible, (index - 1, n))
        end
    end
    pairs = Any[]
    for a in 1:length(eligible)
        for b in (a + 1):length(eligible)
            g = gcd(eligible[a][2], eligible[b][2])
            if g > 1 && g != eligible[a][2] && g != eligible[b][2]
                push!(pairs, Dict{String,Any}(
                    "i" => eligible[a][1],
                    "j" => eligible[b][1],
                    "shared" => true,
                ))
            end
        end
    end
    return pairs
end

function handle_analyze(req)
    if !(req isa AbstractDict)
        return refuse("bad_request")
    end
    if has_private_field(req)
        return refuse("private_field")
    end
    op = string(get(req, "op", ""))
    if op == "inspect"
        n = try
            parse(BigInt, string(req["n"]))
        catch
            return refuse("modulus")
        end
        e = try
            parse(BigInt, string(get(req, "e", "65537")))
        catch
            return refuse("exponent")
        end
        reasons, bits = public_reasons(n, e, string(get(req, "sig_alg", "")))
        return Dict{String,Any}("ok" => true, "reasons" => reasons, "bits" => bits)
    elseif op == "batch_gcd"
        moduli = get(req, "moduli", nothing)
        if !(moduli isa AbstractVector)
            return refuse("moduli")
        end
        pairs = try
            batch_pairs(moduli)
        catch
            return refuse("moduli")
        end
        return Dict{String,Any}("ok" => true, "pairs" => pairs)
    end
    return refuse("unknown_op")
end

function parse_components(entry)
    n = parse(BigInt, string(entry["n"]))
    e = parse(BigInt, string(entry["e"]))
    d = parse(BigInt, string(entry["d"]))
    p = parse(BigInt, string(entry["p"]))
    q = parse(BigInt, string(entry["q"]))
    return n, e, d, p, q
end

function consistent(n, e, d, p, q)
    n == p * q && mod(e * d, (p - 1) * (q - 1)) == 1
end

function confirm_record(profile::AbstractString, entry)
    n, e, d, p, q = parse_components(entry)
    if ndigits2(n) > MAX_ORACLE_BITS || ndigits2(p) > MAX_ORACLE_BITS || ndigits2(q) > MAX_ORACLE_BITS
        return false, true
    end
    ok = consistent(n, e, d, p, q)
    if profile == "weak_rsa"
        ok = ok && e == 65537
    elseif profile == "roca"
        ok = ok && roca_fingerprint(n)
    elseif profile == "wiener"
        ok = ok && d < isqrt(isqrt(n)) && ndigits2(e) * 2 > ndigits2(n)
    elseif profile == "fermat"
        gap = abs(p - q)
        ok = ok && gap > 0 && gap < BigInt(2)^64
    end
    return ok, false
end

function handle_oracle(req)
    if !(req isa AbstractDict)
        return refuse("bad_request")
    end
    if string(get(req, "origin", "")) != "synthetic"
        return refuse("origin")
    end
    profile = string(get(req, "profile", ""))
    if profile != "shared_prime" && profile != "weak_rsa" && profile != "roca" && profile != "wiener" && profile != "fermat"
        return refuse("profile")
    end
    if profile == "shared_prime"
        keys = get(req, "keys", nothing)
        if !(keys isa AbstractVector) || length(keys) != 2
            return refuse("shape")
        end
        try
            left, size_refused = confirm_record("shared_prime", keys[1])
            right, size_refused_b = confirm_record("shared_prime", keys[2])
            if size_refused || size_refused_b
                return refuse("size")
            end
            n1 = parse(BigInt, string(keys[1]["n"]))
            n2 = parse(BigInt, string(keys[2]["n"]))
            g = gcd(n1, n2)
            shared = g > 1 && g != n1 && g != n2
            return Dict{String,Any}(
                "ok" => true,
                "confirmed" => left && right && shared,
                "profile" => profile,
            )
        catch
            return refuse("components")
        end
    end
    try
        confirmed, size_refused = confirm_record(profile, req)
        if size_refused
            return refuse("size")
        end
        return Dict{String,Any}("ok" => true, "confirmed" => confirmed, "profile" => profile)
    catch
        return refuse("components")
    end
end

end
