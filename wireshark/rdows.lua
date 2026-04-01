-- rdows.lua — Wireshark dissector for RDoWS (RDMA over WebSockets)

local rdows_proto = Proto("rdows", "RDMA over WebSockets")

-- ---------------------------------------------------------------------------
-- Header fields (24 bytes)
-- ---------------------------------------------------------------------------

local f_version      = ProtoField.uint8("rdows.version", "Version", base.HEX)
local f_opcode       = ProtoField.uint8("rdows.opcode", "Opcode", base.HEX)
local f_flags        = ProtoField.uint16("rdows.flags", "Flags", base.HEX)
local f_flag_f       = ProtoField.bool("rdows.flags.fragment", "Fragment", 16, nil, 0x8000)
local f_flag_l       = ProtoField.bool("rdows.flags.last", "Last Fragment", 16, nil, 0x4000)
local f_flag_s       = ProtoField.bool("rdows.flags.solicited", "Solicited", 16, nil, 0x2000)
local f_session_id   = ProtoField.uint32("rdows.session_id", "Session ID", base.HEX)
local f_sequence     = ProtoField.uint32("rdows.sequence", "Sequence Number", base.DEC)
local f_wrid         = ProtoField.uint64("rdows.wrid", "Work Request ID", base.DEC)
local f_payload_len  = ProtoField.uint32("rdows.payload_length", "Payload Length", base.DEC)

-- ---------------------------------------------------------------------------
-- Payload fields
-- ---------------------------------------------------------------------------

-- CONNECT / CONNECT_ACK
local f_pd_handle    = ProtoField.uint32("rdows.pd", "PD Handle", base.HEX)
local f_cap_flags    = ProtoField.uint32("rdows.capability_flags", "Capability Flags", base.HEX)
local f_max_msg_size = ProtoField.uint32("rdows.max_msg_size", "Max Message Size", base.DEC)
local f_icc          = ProtoField.uint32("rdows.icc", "Initial Credit Count", base.DEC)

-- MR_REG
local f_access_flags = ProtoField.uint32("rdows.access_flags", "Access Flags", base.HEX)
local f_region_len   = ProtoField.uint64("rdows.region_len", "Region Length", base.DEC)

-- MR_REG_ACK
local f_lkey         = ProtoField.uint32("rdows.lkey", "L_Key", base.HEX)
local f_rkey         = ProtoField.uint32("rdows.rkey", "R_Key", base.HEX)
local f_status       = ProtoField.uint16("rdows.status", "Status", base.HEX)

-- WRITE
local f_remote_va    = ProtoField.uint64("rdows.remote_va", "Remote VA", base.HEX)
local f_write_len    = ProtoField.uint64("rdows.length", "Length", base.DEC)

-- READ_REQ
local f_read_len     = ProtoField.uint64("rdows.read_len", "Read Length", base.DEC)
local f_local_lkey   = ProtoField.uint32("rdows.local_lkey", "Local L_Key", base.HEX)
local f_local_va     = ProtoField.uint64("rdows.local_va", "Local VA", base.HEX)

-- READ_RESP
local f_frag_offset  = ProtoField.uint64("rdows.fragment_offset", "Fragment Offset", base.DEC)

-- ATOMIC_REQ
local f_atomic_type  = ProtoField.uint8("rdows.atomic_type", "Atomic Type", base.HEX)
local f_operand1     = ProtoField.uint64("rdows.operand1", "Operand 1", base.DEC)
local f_operand2     = ProtoField.uint64("rdows.operand2", "Operand 2", base.DEC)

-- ATOMIC_RESP
local f_orig_value   = ProtoField.uint64("rdows.original_value", "Original Value", base.DEC)

-- ERROR
local f_error_code   = ProtoField.uint16("rdows.error_code", "Error Code", base.HEX)
local f_failing_seq  = ProtoField.uint32("rdows.failing_seq", "Failing Sequence", base.DEC)
local f_desc_len     = ProtoField.uint16("rdows.desc_len", "Description Length", base.DEC)
local f_desc         = ProtoField.string("rdows.description", "Description")

-- CREDIT_UPDATE
local f_credit_inc   = ProtoField.uint32("rdows.credit_increment", "Credit Increment", base.DEC)

-- SG Entry
local f_sg_count     = ProtoField.uint16("rdows.sg_count", "SG Entry Count", base.DEC)
local f_sg_lkey      = ProtoField.uint32("rdows.sg.lkey", "SG L_Key", base.HEX)
local f_sg_offset    = ProtoField.uint64("rdows.sg.offset", "SG Offset", base.DEC)
local f_sg_length    = ProtoField.uint32("rdows.sg.length", "SG Length", base.DEC)

-- Data payload
local f_data         = ProtoField.bytes("rdows.data", "Data")

rdows_proto.fields = {
    f_version, f_opcode, f_flags, f_flag_f, f_flag_l, f_flag_s,
    f_session_id, f_sequence, f_wrid, f_payload_len,
    f_pd_handle, f_cap_flags, f_max_msg_size, f_icc,
    f_access_flags, f_region_len,
    f_lkey, f_rkey, f_status,
    f_remote_va, f_write_len,
    f_read_len, f_local_lkey, f_local_va,
    f_frag_offset,
    f_atomic_type, f_operand1, f_operand2,
    f_orig_value,
    f_error_code, f_failing_seq, f_desc_len, f_desc,
    f_credit_inc,
    f_sg_count, f_sg_lkey, f_sg_offset, f_sg_length,
    f_data,
}

-- ---------------------------------------------------------------------------
-- Lookup tables
-- ---------------------------------------------------------------------------

local opcode_names = {
    [0x01] = "CONNECT",
    [0x02] = "CONNECT_ACK",
    [0x03] = "DISCONNECT",
    [0x10] = "MR_REG",
    [0x11] = "MR_REG_ACK",
    [0x12] = "MR_DEREG",
    [0x13] = "MR_DEREG_ACK",
    [0x20] = "SEND",
    [0x21] = "SEND_DATA",
    [0x22] = "RECV_COMP",
    [0x30] = "WRITE",
    [0x31] = "WRITE_DATA",
    [0x32] = "WRITE_COMP",
    [0x40] = "READ_REQ",
    [0x41] = "READ_RESP",
    [0x50] = "ATOMIC_REQ",
    [0x51] = "ATOMIC_RESP",
    [0x60] = "ACK",
    [0x61] = "CREDIT_UPDATE",
    [0xF0] = "ERROR",
}

local error_names = {
    [0x0000] = "SUCCESS",
    [0x0001] = "ERR_PROTO_VERSION",
    [0x0002] = "ERR_UNKNOWN_OPCODE",
    [0x0003] = "ERR_INVALID_PD",
    [0x0004] = "ERR_INVALID_LKEY",
    [0x0005] = "ERR_INVALID_MKEY",
    [0x0006] = "ERR_ACCESS_DENIED",
    [0x0007] = "ERR_BOUNDS",
    [0x0008] = "ERR_ALIGNMENT",
    [0x0009] = "ERR_PAYLOAD_SIZE",
    [0x0010] = "ERR_RNR",
    [0x0020] = "ERR_CQ_OVERFLOW",
    [0x0030] = "ERR_SEQ_GAP",
    [0x0040] = "ERR_TIMEOUT",
    [0xFFFF] = "ERR_INTERNAL",
}

local atomic_type_names = {
    [0x01] = "Compare-and-Swap",
    [0x02] = "Fetch-and-Add",
}

local function access_flags_str(flags)
    local parts = {}
    if bit.band(flags, 0x01) ~= 0 then table.insert(parts, "LOCAL_WRITE") end
    if bit.band(flags, 0x02) ~= 0 then table.insert(parts, "REMOTE_WRITE") end
    if bit.band(flags, 0x04) ~= 0 then table.insert(parts, "REMOTE_READ") end
    if bit.band(flags, 0x08) ~= 0 then table.insert(parts, "REMOTE_ATOMIC") end
    if #parts == 0 then return "NONE" end
    return table.concat(parts, "|")
end

-- ---------------------------------------------------------------------------
-- SG entry parsing helper
-- ---------------------------------------------------------------------------

local SG_ENTRY_SIZE = 16

local function parse_sg_entries(buffer, offset, count, tree)
    local total_bytes = 0
    for i = 0, count - 1 do
        local base = offset + i * SG_ENTRY_SIZE
        if base + SG_ENTRY_SIZE > buffer:len() then break end

        local sg_tree = tree:add(rdows_proto, buffer(base, SG_ENTRY_SIZE),
            string.format("SG Entry [%d]", i))
        sg_tree:add(f_sg_lkey, buffer(base, 4))
        sg_tree:add(f_sg_offset, buffer(base + 4, 8))
        sg_tree:add(f_sg_length, buffer(base + 12, 4))

        total_bytes = total_bytes + buffer(base + 12, 4):uint()
    end
    return total_bytes
end

-- ---------------------------------------------------------------------------
-- Main dissector
-- ---------------------------------------------------------------------------

function rdows_proto.dissector(buffer, pinfo, tree)
    if buffer:len() < 24 then return end

    local version     = buffer(0, 1):uint()
    local opcode      = buffer(1, 1):uint()
    local flags       = buffer(2, 2):uint()
    local session_id  = buffer(4, 4):uint()
    local seq         = buffer(8, 4):uint()
    local wrid        = buffer(12, 8):uint64()
    local payload_len = buffer(20, 4):uint()

    local op_name = opcode_names[opcode] or string.format("UNKNOWN(0x%02X)", opcode)

    pinfo.cols.protocol = "RDoWS"

    -- Add header subtree
    local subtree = tree:add(rdows_proto, buffer(), "RDoWS " .. op_name)
    local hdr_tree = subtree:add(rdows_proto, buffer(0, 24), "Header")
    hdr_tree:add(f_version, buffer(0, 1))
    hdr_tree:add(f_opcode, buffer(1, 1)):append_text(" (" .. op_name .. ")")
    local flags_item = hdr_tree:add(f_flags, buffer(2, 2))
    flags_item:add(f_flag_f, buffer(2, 2))
    flags_item:add(f_flag_l, buffer(2, 2))
    flags_item:add(f_flag_s, buffer(2, 2))
    hdr_tree:add(f_session_id, buffer(4, 4))
    hdr_tree:add(f_sequence, buffer(8, 4))
    hdr_tree:add(f_wrid, buffer(12, 8))
    hdr_tree:add(f_payload_len, buffer(20, 4))

    -- Parse payload based on opcode
    local payload_offset = 24
    local remaining = buffer:len() - payload_offset

    if remaining <= 0 and payload_len > 0 then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Payload missing")
        pinfo.cols.info = op_name
        return
    end

    -- CONNECT (0x01)
    if opcode == 0x01 then
        if remaining >= 16 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, 16), "Connect Payload")
            ptree:add(f_pd_handle, buffer(payload_offset, 4))
            ptree:add(f_cap_flags, buffer(payload_offset + 4, 4))
            ptree:add(f_max_msg_size, buffer(payload_offset + 8, 4))
            ptree:add(f_icc, buffer(payload_offset + 12, 4))
        end
        pinfo.cols.info = string.format("CONNECT Session=0x%08X MaxMsg=%d",
            session_id, remaining >= 16 and buffer(payload_offset + 8, 4):uint() or 0)

    -- CONNECT_ACK (0x02)
    elseif opcode == 0x02 then
        if remaining >= 16 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, 16), "Connect Ack Payload")
            ptree:add(f_pd_handle, buffer(payload_offset, 4))
            ptree:add(f_cap_flags, buffer(payload_offset + 4, 4))
            ptree:add(f_max_msg_size, buffer(payload_offset + 8, 4))
            ptree:add(f_icc, buffer(payload_offset + 12, 4))
        end
        pinfo.cols.info = string.format("CONNECT_ACK Session=0x%08X ICC=%d",
            session_id, remaining >= 16 and buffer(payload_offset + 12, 4):uint() or 0)

    -- DISCONNECT (0x03)
    elseif opcode == 0x03 then
        pinfo.cols.info = string.format("DISCONNECT Session=0x%08X", session_id)

    -- MR_REG (0x10)
    elseif opcode == 0x10 then
        if remaining >= 16 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, math.min(remaining, 20)),
                "MR_REG Payload")
            ptree:add(f_pd_handle, buffer(payload_offset, 4))
            local af = buffer(payload_offset + 4, 4):uint()
            ptree:add(f_access_flags, buffer(payload_offset + 4, 4)):append_text(
                " (" .. access_flags_str(af) .. ")")
            ptree:add(f_region_len, buffer(payload_offset + 8, 8))
            if remaining >= 20 then
                ptree:add(f_lkey, buffer(payload_offset + 16, 4)):append_text(" (suggested)")
            end

            local rlen = buffer(payload_offset + 8, 8):uint64()
            pinfo.cols.info = string.format("MR_REG PD=0x%08X Len=%s Flags=%s",
                buffer(payload_offset, 4):uint(), tostring(rlen), access_flags_str(af))
        else
            pinfo.cols.info = "MR_REG"
        end

    -- MR_REG_ACK (0x11)
    elseif opcode == 0x11 then
        if remaining >= 16 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, 16), "MR_REG_ACK Payload")
            ptree:add(f_pd_handle, buffer(payload_offset, 4))
            ptree:add(f_lkey, buffer(payload_offset + 4, 4))
            ptree:add(f_rkey, buffer(payload_offset + 8, 4))
            ptree:add(f_status, buffer(payload_offset + 12, 2))
            pinfo.cols.info = string.format("MR_REG_ACK L_Key=0x%08X R_Key=0x%08X",
                buffer(payload_offset + 4, 4):uint(), buffer(payload_offset + 8, 4):uint())
        else
            pinfo.cols.info = "MR_REG_ACK"
        end

    -- MR_DEREG (0x12)
    elseif opcode == 0x12 then
        if remaining >= 8 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, 8), "MR_DEREG Payload")
            ptree:add(f_pd_handle, buffer(payload_offset, 4))
            ptree:add(f_lkey, buffer(payload_offset + 4, 4))
            pinfo.cols.info = string.format("MR_DEREG PD=0x%08X L_Key=0x%08X",
                buffer(payload_offset, 4):uint(), buffer(payload_offset + 4, 4):uint())
        else
            pinfo.cols.info = "MR_DEREG"
        end

    -- MR_DEREG_ACK (0x13)
    elseif opcode == 0x13 then
        if remaining >= 8 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, 8), "MR_DEREG_ACK Payload")
            local st = buffer(payload_offset, 2):uint()
            ptree:add(f_status, buffer(payload_offset, 2))
            local st_name = error_names[st] or string.format("0x%04X", st)
            pinfo.cols.info = string.format("MR_DEREG_ACK Status=%s", st_name)
        else
            pinfo.cols.info = "MR_DEREG_ACK"
        end

    -- SEND (0x20)
    elseif opcode == 0x20 then
        if remaining >= 4 then
            local sg_count = buffer(payload_offset, 2):uint()
            local sg_data_len = math.min(remaining, 4 + sg_count * SG_ENTRY_SIZE)
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, sg_data_len), "Send Payload")
            ptree:add(f_sg_count, buffer(payload_offset, 2))
            local total_bytes = parse_sg_entries(buffer, payload_offset + 4, sg_count, ptree)
            pinfo.cols.info = string.format("SEND [%d SG entr%s, %d bytes]",
                sg_count, sg_count == 1 and "y" or "ies", total_bytes)
        else
            pinfo.cols.info = "SEND"
        end

    -- SEND_DATA (0x21)
    elseif opcode == 0x21 then
        if remaining > 0 then
            subtree:add(f_data, buffer(payload_offset, remaining))
        end
        pinfo.cols.info = string.format("SEND_DATA [%d bytes]", payload_len)

    -- RECV_COMP (0x22)
    elseif opcode == 0x22 then
        pinfo.cols.info = string.format("RECV_COMP WRID=%s", tostring(wrid))

    -- WRITE (0x30)
    elseif opcode == 0x30 then
        if remaining >= 24 then
            local rk = buffer(payload_offset, 4):uint()
            local va = buffer(payload_offset + 8, 8):uint64()
            local wlen = buffer(payload_offset + 16, 8):uint64()

            local ptree = subtree:add(rdows_proto, buffer(payload_offset, math.min(remaining, payload_len)),
                "Write Payload")
            ptree:add(f_rkey, buffer(payload_offset, 4))
            ptree:add(f_remote_va, buffer(payload_offset + 8, 8))
            ptree:add(f_write_len, buffer(payload_offset + 16, 8))

            local sg_count = 0
            if remaining > 24 then
                sg_count = (remaining - 24) / SG_ENTRY_SIZE
                parse_sg_entries(buffer, payload_offset + 24, sg_count, ptree)
            end

            pinfo.cols.info = string.format("WRITE R_Key=0x%08X VA=0x%s %s bytes",
                rk, tostring(va), tostring(wlen))
        else
            pinfo.cols.info = "WRITE"
        end

    -- WRITE_DATA (0x31)
    elseif opcode == 0x31 then
        if remaining > 0 then
            subtree:add(f_data, buffer(payload_offset, remaining))
        end
        pinfo.cols.info = string.format("WRITE_DATA [%d bytes]", payload_len)

    -- WRITE_COMP (0x32)
    elseif opcode == 0x32 then
        pinfo.cols.info = string.format("WRITE_COMP WRID=%s", tostring(wrid))

    -- READ_REQ (0x40)
    elseif opcode == 0x40 then
        if remaining >= 40 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, 40), "Read Request Payload")
            ptree:add(f_rkey, buffer(payload_offset, 4))
            ptree:add(f_remote_va, buffer(payload_offset + 8, 8))
            ptree:add(f_read_len, buffer(payload_offset + 16, 8))
            ptree:add(f_local_lkey, buffer(payload_offset + 24, 4))
            ptree:add(f_local_va, buffer(payload_offset + 32, 8))

            local rk = buffer(payload_offset, 4):uint()
            local va = buffer(payload_offset + 8, 8):uint64()
            local rlen = buffer(payload_offset + 16, 8):uint64()
            pinfo.cols.info = string.format("READ_REQ R_Key=0x%08X VA=0x%s Len=%s",
                rk, tostring(va), tostring(rlen))
        else
            pinfo.cols.info = "READ_REQ"
        end

    -- READ_RESP (0x41)
    elseif opcode == 0x41 then
        if remaining >= 8 then
            local fo = buffer(payload_offset, 8):uint64()
            local data_len = remaining - 8
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, remaining),
                "Read Response Payload")
            ptree:add(f_frag_offset, buffer(payload_offset, 8))
            if data_len > 0 then
                ptree:add(f_data, buffer(payload_offset + 8, data_len))
            end
            pinfo.cols.info = string.format("READ_RESP Offset=%s [%d bytes]",
                tostring(fo), data_len)
        else
            pinfo.cols.info = "READ_RESP"
        end

    -- ATOMIC_REQ (0x50)
    elseif opcode == 0x50 then
        if remaining >= 32 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, 32),
                "Atomic Request Payload")
            ptree:add(f_rkey, buffer(payload_offset, 4))
            local at = buffer(payload_offset + 4, 1):uint()
            local at_name = atomic_type_names[at] or string.format("0x%02X", at)
            ptree:add(f_atomic_type, buffer(payload_offset + 4, 1)):append_text(
                " (" .. at_name .. ")")
            ptree:add(f_remote_va, buffer(payload_offset + 8, 8))
            ptree:add(f_operand1, buffer(payload_offset + 16, 8))
            ptree:add(f_operand2, buffer(payload_offset + 24, 8))

            local rk = buffer(payload_offset, 4):uint()
            local va = buffer(payload_offset + 8, 8):uint64()
            local short_name = at == 0x01 and "CAS" or (at == 0x02 and "FAA" or at_name)
            pinfo.cols.info = string.format("ATOMIC_REQ %s R_Key=0x%08X VA=0x%s",
                short_name, rk, tostring(va))
        else
            pinfo.cols.info = "ATOMIC_REQ"
        end

    -- ATOMIC_RESP (0x51)
    elseif opcode == 0x51 then
        if remaining >= 16 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, 16),
                "Atomic Response Payload")
            ptree:add(f_orig_value, buffer(payload_offset, 8))
            ptree:add(f_status, buffer(payload_offset + 8, 2))
            local ov = buffer(payload_offset, 8):uint64()
            pinfo.cols.info = string.format("ATOMIC_RESP Original=%s", tostring(ov))
        else
            pinfo.cols.info = "ATOMIC_RESP"
        end

    -- ACK (0x60)
    elseif opcode == 0x60 then
        pinfo.cols.info = string.format("ACK Seq=%d", seq)

    -- CREDIT_UPDATE (0x61)
    elseif opcode == 0x61 then
        if remaining >= 4 then
            local ptree = subtree:add(rdows_proto, buffer(payload_offset, math.min(remaining, 8)),
                "Credit Update Payload")
            ptree:add(f_credit_inc, buffer(payload_offset, 4))
            local inc = buffer(payload_offset, 4):uint()
            pinfo.cols.info = string.format("CREDIT_UPDATE +%d", inc)
        else
            pinfo.cols.info = "CREDIT_UPDATE"
        end

    -- ERROR (0xF0)
    elseif opcode == 0xF0 then
        if remaining >= 10 then
            local ec = buffer(payload_offset, 2):uint()
            local ec_name = error_names[ec] or string.format("0x%04X", ec)
            local fseq = buffer(payload_offset + 4, 4):uint()
            local dlen = buffer(payload_offset + 8, 2):uint()

            local ptree = subtree:add(rdows_proto, buffer(payload_offset, math.min(remaining, 10 + dlen)),
                "Error Payload")
            ptree:add(f_error_code, buffer(payload_offset, 2)):append_text(" (" .. ec_name .. ")")
            ptree:add(f_failing_seq, buffer(payload_offset + 4, 4))
            ptree:add(f_desc_len, buffer(payload_offset + 8, 2))

            local desc_str = ""
            if dlen > 0 and remaining >= 10 + dlen then
                ptree:add(f_desc, buffer(payload_offset + 10, dlen))
                desc_str = buffer(payload_offset + 10, dlen):string()
            end

            if #desc_str > 0 then
                pinfo.cols.info = string.format('ERROR %s Seq=%d "%s"', ec_name, fseq, desc_str)
            else
                pinfo.cols.info = string.format("ERROR %s Seq=%d", ec_name, fseq)
            end
        else
            pinfo.cols.info = "ERROR"
        end

    -- Unknown opcode
    else
        pinfo.cols.info = string.format("RDoWS %s Seq=%d", op_name, seq)
    end
end

-- ---------------------------------------------------------------------------
-- Registration
-- ---------------------------------------------------------------------------

-- Subprotocol-based dissector routing (Wireshark routes "rdows.v1" here)
local ws_dissector_table = DissectorTable.get("ws.protocol")
ws_dissector_table:add("rdows.v1", rdows_proto)

-- Fallback heuristic dissector
local function rdows_heuristic(buffer, pinfo, tree)
    if buffer:len() < 24 then return false end
    local version = buffer(0, 1):uint()
    local opcode = buffer(1, 1):uint()
    if version ~= 0x01 then return false end
    if opcode_names[opcode] == nil then return false end
    rdows_proto.dissector(buffer, pinfo, tree)
    return true
end

rdows_proto:register_heuristic("ws", rdows_heuristic)
