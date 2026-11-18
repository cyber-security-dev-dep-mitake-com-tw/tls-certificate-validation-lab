using Test
using LabCrypto

function response_text(value)
    return LabCrypto.JSON.encode(value)
end

@testset "json" begin
    parsed = LabCrypto.JSON.parse("{\"ok\":true,\"n\":[1,\"ab\"]}")
    @test parsed["ok"] == true
    @test parsed["n"][2] == "ab"
end

@testset "gates" begin
    @test LabCrypto.handle_generate(Dict("profile" => "weak_rsa", "bits" => 2048, "origin" => "synthetic"))["refused"] == true
    @test LabCrypto.handle_generate(Dict("profile" => "weak_rsa", "bits" => 512, "origin" => "harvested"))["refused"] == true
    @test LabCrypto.handle_generate(Dict("op" => "factor", "n" => "15", "origin" => "synthetic", "bits" => 512, "profile" => "weak_rsa"))["refused"] == true
    @test LabCrypto.handle_analyze(Dict("op" => "inspect", "n" => "15", "e" => "3", "d" => "1"))["refused"] == true
    huge = string(BigInt(1) << 2048)
    refused = LabCrypto.handle_oracle(Dict(
        "profile" => "weak_rsa",
        "origin" => "synthetic",
        "n" => huge,
        "e" => "65537",
        "d" => "1",
        "p" => "3",
        "q" => "5",
    ))
    @test refused["refused"] == true
    harvested = LabCrypto.handle_oracle(Dict("profile" => "weak_rsa", "origin" => "harvested", "n" => "15"))
    @test harvested["refused"] == true
    @test !occursin("factor", response_text(harvested))
end

@testset "public analysis does not return factors" begin
    normal = LabCrypto.handle_analyze(Dict(
        "op" => "inspect",
        "n" => string((BigInt(1) << 2047) + 1),
        "e" => "65537",
        "sig_alg" => "sha256WithRSAEncryption",
    ))
    @test normal["ok"] == true
    @test !("WEAK_KEY" in normal["reasons"])
    @test !("STRUCTURAL_WEAKNESS" in normal["reasons"])
    text = response_text(normal)
    @test !occursin("\"d\"", text)
    @test !occursin("factor", text)
end

@testset "synthetic fixtures" begin
    profiles = ("weak_rsa", "roca", "wiener", "fermat")
    for profile in profiles
        generated = LabCrypto.handle_generate(Dict("profile" => profile, "bits" => 512, "origin" => "synthetic"))
        @test generated["ok"] == true
        key = generated["keys"][1]
        @test ndigits(parse(BigInt, key["n"]), base=2) <= 512
        request = Dict{String,Any}("profile" => profile, "origin" => "synthetic")
        merge!(request, key)
        confirmed = LabCrypto.handle_oracle(request)
        @test confirmed["ok"] == true
        @test confirmed["confirmed"] == true
        echo = response_text(confirmed)
        @test !occursin(key["d"], echo)
        @test !occursin(key["p"], echo)
        inspected = LabCrypto.handle_analyze(Dict(
            "op" => "inspect",
            "n" => key["n"],
            "e" => key["e"],
            "sig_alg" => "sha256WithRSAEncryption",
        ))
        @test inspected["ok"] == true
        if profile == "weak_rsa" || profile == "fermat"
            @test "WEAK_KEY" in inspected["reasons"]
        elseif profile == "roca"
            @test "ROCA_FINGERPRINT" in inspected["reasons"]
        elseif profile == "wiener"
            @test "STRUCTURAL_WEAKNESS" in inspected["reasons"]
        end
        @test !occursin(key["p"], response_text(inspected))
    end

    generated = LabCrypto.handle_generate(Dict("profile" => "shared_prime", "bits" => 512, "origin" => "synthetic"))
    @test generated["ok"] == true
    keys = generated["keys"]
    confirmed = LabCrypto.handle_oracle(Dict("profile" => "shared_prime", "origin" => "synthetic", "keys" => keys))
    @test confirmed["confirmed"] == true
    @test !occursin(keys[1]["p"], response_text(confirmed))
    p = keys[1]["p"]
    batch = LabCrypto.handle_analyze(Dict(
        "op" => "batch_gcd",
        "moduli" => Any[keys[1]["n"], keys[2]["n"], string(BigInt(1) << 2048)],
    ))
    @test batch["pairs"][1]["shared"] == true
    @test batch["pairs"][1]["i"] == 0
    @test batch["pairs"][1]["j"] == 1
    text = response_text(batch)
    @test !occursin(p, text)
    @test !occursin("factor", text)

    sha1 = LabCrypto.handle_analyze(Dict(
        "op" => "inspect",
        "n" => string((BigInt(1) << 2047) + 3),
        "e" => "65537",
        "sig_alg" => "sha1WithRSAEncryption",
    ))
    @test "WEAK_SIGNATURE" in sha1["reasons"]
end
