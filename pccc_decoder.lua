-- PCCC Address Decoder for Wireshark
-- Decodes PCCC data from CIP encapsulated PCCC messages
-- Supports MicroLogix 1100 and other Allen-Bradley PLCs using PCCC over EtherNet/IP

local pccc_decoder = Proto("pccc_addr", "PCCC Address Decoder")

-- Define fields
local f_file_type = ProtoField.uint8("pccc_addr.file_type", "File Type", base.HEX)
local f_file_type_str = ProtoField.string("pccc_addr.file_type_str", "File Type String")
local f_file_num = ProtoField.uint8("pccc_addr.file_num", "File Number", base.DEC)
local f_element = ProtoField.uint8("pccc_addr.element", "Element (Word)", base.DEC)
local f_subelement = ProtoField.uint8("pccc_addr.subelement", "Subelement", base.HEX)
local f_bit = ProtoField.int8("pccc_addr.bit", "Bit Number", base.DEC)
local f_address = ProtoField.string("pccc_addr.address", "Decoded Address")
local f_or_mask = ProtoField.uint16("pccc_addr.or_mask", "OR Mask (Set Bits)", base.HEX)
local f_and_mask = ProtoField.uint16("pccc_addr.and_mask", "AND Mask (Clear Bits)", base.HEX)
local f_bit_value = ProtoField.uint8("pccc_addr.bit_value", "Bit Value Written", base.DEC)
local f_operation = ProtoField.string("pccc_addr.operation", "Operation Summary")

pccc_decoder.fields = {
    f_file_type, f_file_type_str, f_file_num, 
    f_element, f_subelement, f_bit, f_address, 
    f_or_mask, f_and_mask, f_bit_value, f_operation
}

-- Initialize field extractor at script level (MUST be here, not in function)
local cip_pccc_data_field = Field.new("cip.pccc.data")

-- File type lookup table
local file_types = {
    [0x82] = "O:",  -- Output
    [0x83] = "I:",  -- Input
    [0x84] = "S:",  -- Status
    [0x85] = "B:",  -- Binary
    [0x89] = "N:",  -- Integer
    [0x8A] = "F:",  -- Float
    [0x8B] = "O:",  -- Output logical by slot
    [0x8C] = "I:"   -- Input logical by slot
}

-- Helper function to check if a bit is set
local function is_bit_set(value, bit_position)
    local mask = bit.lshift(1, bit_position)
    return bit.band(value, mask) ~= 0
end

-- Helper function to find bit position from mask (returns nil if mask is 0 or has multiple bits)
local function get_bit_position(mask)
    if mask == 0 then return nil end
    
    -- Check if only one bit is set (power of 2)
    if bit.band(mask, mask - 1) ~= 0 then
        return nil  -- Multiple bits set
    end
    
    -- Find which bit is set
    for i = 0, 15 do
        if bit.band(mask, bit.lshift(1, i)) ~= 0 then
            return i
        end
    end
    return nil
end

function pccc_decoder.dissector(buffer, pinfo, tree)
    -- Get the CIP PCCC data field
    local cip_pccc_data = cip_pccc_data_field()
    
    -- Exit if no PCCC data present
    if not cip_pccc_data then
        return
    end
    
    -- Get the data range and convert to bytes
    local data_range = cip_pccc_data.range
    local data = data_range:bytes()
    
    -- Need at least 6 bytes to decode address
    if data:len() < 6 then
        return
    end
    
    -- Parse the PCCC data structure
    local byte_count = data:get_index(0) + (data:get_index(1) * 256)
    local file_type = data:get_index(2)
    local file_num = data:get_index(3)      -- Single byte file number
    local element = data:get_index(4)       -- Element is 0-indexed
    local subelement = data:get_index(5)
    
    -- Create subtree using the actual data range from CIP
    local subtree = tree:add(pccc_decoder, data_range, "PCCC Address Decoder")
    
    -- Add file type with proper byte highlighting
    subtree:add(f_file_type, data_range(2, 1), file_type)
    
    local file_type_str = file_types[file_type] or string.format("Unknown(0x%02X)", file_type)
    subtree:add(f_file_type_str, file_type_str)
    
    -- Add other fields with byte range highlighting
    subtree:add(f_file_num, data_range(3, 1), file_num)
    subtree:add(f_element, data_range(4, 1), element)
    subtree:add(f_subelement, data_range(5, 1), subelement)
    
    -- Decode address based on subelement value
    local address_str = ""
    local bit_num = nil
    
    -- Try to decode subelement as a bitmask (single bit set = power of 2)
    bit_num = get_bit_position(subelement)
    if bit_num then
        -- Subelement is a valid single-bit mask
        subtree:add(f_bit, bit_num)
        address_str = string.format("%s%d.%d/%d", file_type_str, file_num, element, bit_num)
    elseif subelement == 0x00 then
        -- Special format - bit number comes from bytes 6-7
        address_str = string.format("%s%d.%d", file_type_str, file_num, element)
    else
        -- Unknown or multi-bit operation
        address_str = string.format("%s%d.%d", file_type_str, file_num, element)
    end
    
    -- Add decoded address as generated field
    local addr_item = subtree:add(f_address, address_str)
    addr_item:set_generated()
    
    -- Decode bit value and masks
    local bit_value = nil
    local operation_str = ""
    
    if data:len() >= 9 then
        if subelement == 0x00 then
            -- SPECIAL FORMAT: When subelement is 0x00
            -- Bytes 6-7: Target bit mask (big-endian)
            -- Byte 8: Value to write (non-zero = 1, zero = 0)
            local target_mask = (data:get_index(6) * 256) + data:get_index(7)
            subtree:add(f_or_mask, data_range(6, 2), target_mask):append_text(" (target bit)")
            
            -- Decode target bit from mask
            bit_num = get_bit_position(target_mask)
            if bit_num then
                subtree:add(f_bit, bit_num):append_text(" (from target mask)")
                address_str = string.format("%s%d.%d/%d", file_type_str, file_num, element, bit_num)
                addr_item:set_text(address_str)
                
                -- Byte 8 contains the value (non-zero = 1, zero = 0)
                local value_byte = data:get_index(8)
                if value_byte ~= 0x00 then
                    bit_value = 1
                    operation_str = string.format("Write %s = 1 (SET)", address_str)
                else
                    bit_value = 0
                    operation_str = string.format("Write %s = 0 (CLEAR)", address_str)
                end
            end
        else
            -- STANDARD MASK FORMAT: When subelement is a bitmask
            -- Bytes 6-7: OR mask (big-endian) - bits to SET
            local or_mask = (data:get_index(6) * 256) + data:get_index(7)
            subtree:add(f_or_mask, data_range(6, 2), or_mask)
            
            -- Bytes 8-9: AND mask (big-endian) - bits to keep (if present)
            local and_mask = 0xFFFF
            if data:len() >= 10 then
                and_mask = (data:get_index(8) * 256) + data:get_index(9)
                subtree:add(f_and_mask, data_range(8, 2), and_mask)
            end
            
            -- For SET operations, OR mask overrides the subelement bit
            local mask_bit = get_bit_position(or_mask)
            if mask_bit then
                bit_num = mask_bit
                address_str = string.format("%s%d.%d/%d", file_type_str, file_num, element, bit_num)
                subtree:add(f_bit, bit_num):append_text(" (from OR mask)")
            end
            
            -- Determine operation
            if bit_num then
                if is_bit_set(or_mask, bit_num) then
                    bit_value = 1
                    operation_str = string.format("Write %s = 1 (SET)", address_str)
                elseif or_mask == 0 then
                    bit_value = 0
                    operation_str = string.format("Write %s = 0 (CLEAR)", address_str)
                elseif not is_bit_set(and_mask, bit_num) then
                    bit_value = 0
                    operation_str = string.format("Write %s = 0 (CLEAR)", address_str)
                end
            end
        end
        
        -- Add bit value and operation summary
        if bit_value ~= nil then
            local value_item = subtree:add(f_bit_value, bit_value)
            value_item:set_generated()
        end
        
        if operation_str ~= "" then
            local op_item = subtree:add(f_operation, operation_str)
            op_item:set_generated()
        end
        
        -- Update info column
        if bit_value ~= nil then
            pcall(function()
                pinfo.cols.info:append(string.format(" [%s=%d]", address_str, bit_value))
            end)
        else
            pcall(function()
                pinfo.cols.info:append(" [" .. address_str .. "]")
            end)
        end
    else
        -- No mask data
        pcall(function()
            pinfo.cols.info:append(" [" .. address_str .. "]")
        end)
    end
end

-- Register as a postdissector (runs after normal dissectors)
register_postdissector(pccc_decoder)