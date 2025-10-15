-- PCCC Address Decoder for Wireshark
-- Decodes PCCC data from CIP encapsulated PCCC messages
-- Supports MicroLogix 1100 and other Allen-Bradley PLCs using PCCC over EtherNet/IP
--
-- PCCC 0xAB Command: "Protected Typed Logical Write with Mask"
-- Specification: new_value = (old_value & ~mask) | (data & mask)
--   - MASK: selects which bits to modify
--   - DATA: provides the new values for those bits

local pccc_decoder = Proto("pccc_addr", "PCCC Address Decoder")

-- Define fields
local f_file_type = ProtoField.uint8("pccc_addr.file_type", "File Type", base.HEX)
local f_file_type_str = ProtoField.string("pccc_addr.file_type_str", "File Type String")
local f_file_num = ProtoField.uint8("pccc_addr.file_num", "File Number", base.DEC)
local f_element = ProtoField.uint8("pccc_addr.element", "Element (Word)", base.DEC)
local f_subelement = ProtoField.uint8("pccc_addr.subelement", "Subelement", base.HEX)
local f_bit = ProtoField.int8("pccc_addr.bit", "Bit Number", base.DEC)
local f_address = ProtoField.string("pccc_addr.address", "Decoded Address")
local f_mask = ProtoField.uint16("pccc_addr.mask", "Bit Selection Mask", base.HEX)
local f_data = ProtoField.uint16("pccc_addr.data", "Data Value", base.HEX)
local f_bit_value = ProtoField.uint8("pccc_addr.bit_value", "Bit Value Written", base.DEC)
local f_operation = ProtoField.string("pccc_addr.operation", "Operation Summary")
local f_is_pccc_write = ProtoField.bool("pccc_addr.is_write", "Is PCCC Write (0xAB)", base.NONE)

pccc_decoder.fields = {
    f_file_type, f_file_type_str, f_file_num, 
    f_element, f_subelement, f_bit, f_address, 
    f_mask, f_data, f_bit_value, f_operation, f_is_pccc_write
}

-- Initialize field extractors at script level
local cip_pccc_data_field = Field.new("cip.pccc.data")
local cip_pccc_fnc_field = Field.new("cip.pccc.fnc.code_0f")

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

-- Helper function to find bit position from mask (returns nil if not a single bit)
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
    local file_num = data:get_index(3)
    local element = data:get_index(4)
    local subelement = data:get_index(5)
    
    -- Create subtree
    local subtree = tree:add(pccc_decoder, data_range, "PCCC Address Decoder")
    
    -- Check if this is a 0xAB write operation for easy filtering
    local fnc_value = cip_pccc_fnc_field()
    if fnc_value and fnc_value.value == 0xab then
        subtree:add(f_is_pccc_write, true):set_generated()
    end
    
    -- Add file type
    subtree:add(f_file_type, data_range(2, 1), file_type)
    
    local file_type_str = file_types[file_type] or string.format("Unknown(0x%02X)", file_type)
    subtree:add(f_file_type_str, file_type_str)
    
    -- Add other fields
    subtree:add(f_file_num, data_range(3, 1), file_num)
    subtree:add(f_element, data_range(4, 1), element)
    subtree:add(f_subelement, data_range(5, 1), subelement)
    
    -- Decode address based on subelement value
    local address_str = ""
    local bit_num = nil
    
    -- Try to decode subelement as a bitmask (single bit = power of 2)
    bit_num = get_bit_position(subelement)
    if bit_num then
        subtree:add(f_bit, bit_num)
        address_str = string.format("%s%d.%d/%d", file_type_str, file_num, element, bit_num)
    elseif subelement == 0x00 then
        -- Word-level or special bit addressing
        address_str = string.format("%s%d.%d", file_type_str, file_num, element)
    else
        -- Unknown or multi-bit operation
        address_str = string.format("%s%d.%d", file_type_str, file_num, element)
    end
    
    local addr_item = subtree:add(f_address, address_str)
    addr_item:set_generated()
    
    -- Decode PCCC 0xAB mask write operation
    -- Spec: new_value = (old_value & ~mask) | (data & mask)
    local bit_value = nil
    local operation_str = ""
    
    if data:len() >= 9 then
        -- PCCC 0xAB format: [address fields] [MASK] [DATA]
        -- Bytes 6-7: MASK - selects which bits to modify (big-endian)
        local mask = (data:get_index(6) * 256) + data:get_index(7)
        subtree:add(f_mask, data_range(6, 2), mask)
        
        -- Determine the target bit from mask
        local mask_bit = get_bit_position(mask)
        if mask_bit then
            bit_num = mask_bit
            address_str = string.format("%s%d.%d/%d", file_type_str, file_num, element, bit_num)
            subtree:add(f_bit, bit_num):append_text(" (from mask)")
            addr_item:set_text(address_str)
        end
        
        if subelement == 0x00 and data:len() == 9 then
            -- SPECIAL FORMAT: Some PLCs use simplified single-byte data for bit operations
            -- when subelement = 0x00 and only 9 bytes total
            -- Byte 8: non-zero = set bit, zero = clear bit
            local data_byte = data:get_index(8)
            subtree:add(f_data, data_byte):append_text(" (single byte format)")
            
            if bit_num then
                if data_byte ~= 0x00 then
                    bit_value = 1
                    operation_str = string.format("Write %s = 1 (SET)", address_str)
                else
                    bit_value = 0
                    operation_str = string.format("Write %s = 0 (CLEAR)", address_str)
                end
            end
        else
            -- STANDARD FORMAT: Bytes 8-9 = DATA value (big-endian)
            -- Operation: new_value = (old_value & ~mask) | (data & mask)
            local data_value = 0
            if data:len() >= 10 then
                data_value = (data:get_index(8) * 256) + data:get_index(9)
                subtree:add(f_data, data_range(8, 2), data_value)
            else
                -- Only 9 bytes - treat byte 8 as low byte of data
                data_value = data:get_index(8)
                subtree:add(f_data, data_value):append_text(" (partial)")
            end
            
            -- Determine bit value using correct mask logic
            -- The bit is SET if: (data & mask) has the bit set
            -- The bit is CLEAR if: (data & mask) has the bit clear
            if bit_num then
                if is_bit_set(data_value, bit_num) then
                    bit_value = 1
                    operation_str = string.format("Write %s = 1 (SET)", address_str)
                else
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
        -- No mask/data present
        pcall(function()
            pinfo.cols.info:append(" [" .. address_str .. "]")
        end)
    end
end

register_postdissector(pccc_decoder)