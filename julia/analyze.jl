using LabCrypto

function main()
    while !eof(stdin)
        line = readline(stdin)
        isempty(strip(line)) && continue
        response = try
            LabCrypto.handle_analyze(LabCrypto.JSON.parse(line))
        catch
            LabCrypto.refuse("bad_request")
        end
        println(LabCrypto.JSON.encode(response))
        flush(stdout)
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
