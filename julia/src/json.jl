# Minimal JSON for the lab protocol. Big integers travel as strings.
module JSON

function parse(text::AbstractString)
    parser = Parser(codeunits(String(text)), 1)
    value = parse_value(parser)
    skip(parser)
    if parser.i <= length(parser.s)
        error("trailing json")
    end
    return value
end

function encode(value)
    buf = IOBuffer()
    write_value(buf, value)
    return String(take!(buf))
end

mutable struct Parser
    s::Base.CodeUnits{UInt8,String}
    i::Int
end

function skip(parser)
    while parser.i <= length(parser.s) && isspace(Char(parser.s[parser.i]))
        parser.i += 1
    end
end

function peek(parser)
    skip(parser)
    parser.i > length(parser.s) && return nothing
    return Char(parser.s[parser.i])
end

function bump(parser)
    ch = peek(parser)
    ch === nothing && error("unexpected end")
    parser.i += 1
    return ch
end

function parse_value(parser)
    ch = peek(parser)
    ch === nothing && error("unexpected end")
    if ch == '{'
        return parse_object(parser)
    elseif ch == '['
        return parse_array(parser)
    elseif ch == '"'
        return parse_string(parser)
    elseif ch == 't'
        consume(parser, "true")
        return true
    elseif ch == 'f'
        consume(parser, "false")
        return false
    elseif ch == 'n'
        consume(parser, "null")
        return nothing
    else
        return parse_number(parser)
    end
end

function consume(parser, literal)
    for ch in literal
        bump(parser) == ch || error("bad literal")
    end
end

function parse_object(parser)
    bump(parser) == '{' || error("object")
    out = Dict{String,Any}()
    if peek(parser) == '}'
        bump(parser)
        return out
    end
    while true
        key = parse_string(parser)
        bump(parser) == ':' || error("colon")
        out[key] = parse_value(parser)
        nxt = bump(parser)
        if nxt == '}'
            return out
        end
        nxt == ',' || error("comma")
    end
end

function parse_array(parser)
    bump(parser) == '[' || error("array")
    out = Any[]
    if peek(parser) == ']'
        bump(parser)
        return out
    end
    while true
        push!(out, parse_value(parser))
        nxt = bump(parser)
        if nxt == ']'
            return out
        end
        nxt == ',' || error("comma")
    end
end

function parse_string(parser)
    bump(parser) == '"' || error("string")
    buf = IOBuffer()
    while parser.i <= length(parser.s)
        ch = Char(parser.s[parser.i])
        parser.i += 1
        if ch == '"'
            return String(take!(buf))
        elseif ch == '\\'
            esc = Char(parser.s[parser.i])
            parser.i += 1
            if esc == 'u'
                hex = String(parser.s[parser.i:parser.i+3])
                parser.i += 4
                print(buf, Char(Base.parse(UInt16, hex; base=16)))
            else
                print(buf, get(Dict('"' => '"', '\\' => '\\', '/' => '/', 'b' => '\b', 'f' => '\f', 'n' => '\n', 'r' => '\r', 't' => '\t'), esc, esc))
            end
        else
            print(buf, ch)
        end
    end
    error("unterminated string")
end

function parse_number(parser)
    start = parser.i
    if peek(parser) == '-'
        parser.i += 1
    end
    while parser.i <= length(parser.s) && isdigit(Char(parser.s[parser.i]))
        parser.i += 1
    end
    parser.i > start || error("number")
    return Base.parse(Int, String(parser.s[start:parser.i-1]))
end

function write_value(io, value)
    if value isa AbstractDict
        print(io, '{')
        first = true
        for (key, item) in value
            first || print(io, ',')
            first = false
            write_value(io, String(key))
            print(io, ':')
            write_value(io, item)
        end
        print(io, '}')
    elseif value isa AbstractVector
        print(io, '[')
        for (index, item) in enumerate(value)
            index == 1 || print(io, ',')
            write_value(io, item)
        end
        print(io, ']')
    elseif value isa AbstractString
        print(io, '"')
        for ch in value
            if ch == '"' || ch == '\\'
                print(io, '\\', ch)
            elseif ch == '\n'
                print(io, "\\n")
            else
                print(io, ch)
            end
        end
        print(io, '"')
    elseif value isa Bool
        print(io, value ? "true" : "false")
    elseif value === nothing
        print(io, "null")
    elseif value isa Integer
        print(io, Int(value))
    else
        error("unsupported json value $(typeof(value))")
    end
end

end
