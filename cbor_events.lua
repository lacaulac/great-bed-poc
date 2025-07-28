-- Chisel description
description = "counts how many times the specified system call has been called"
short_description = "syscall count"
category = "misc"

-- Chisel argument list
--args = {}

args =
{
    -- {
    -- 	name = "syscall_name",
    -- 	description = "the name of the system call to count",
    -- 	argtype = "string"
    -- },
}

cbor = require("cbor")

function string:contains(sub)
    ---@diagnostic disable-next-line: param-type-mismatch
    return self:find(sub, 1, true) ~= nil
end

function string:startswith(start)
    ---@diagnostic disable-next-line: param-type-mismatch
    return self:sub(1, #start) == start
end

function string:endswith(ending)
    ---@diagnostic disable-next-line: param-type-mismatch
    return ending == "" or self:sub(- #ending) == ending
end

function string:replace(old, new)
    local s = self
    local search_start_idx = 1

    while true do
        ---@diagnostic disable-next-line: param-type-mismatch
        local start_idx, end_idx = s:find(old, search_start_idx, true)
        if (not start_idx) then
            break
        end

        ---@diagnostic disable-next-line: param-type-mismatch
        local postfix = s:sub(end_idx + 1)
        ---@diagnostic disable-next-line: param-type-mismatch
        s = s:sub(1, (start_idx - 1)) .. new .. postfix

        search_start_idx = -1 * postfix:len()
    end

    return s
end

function string:insert(pos, text)
    ---@diagnostic disable-next-line: param-type-mismatch
    return self:sub(1, pos - 1) .. text .. self:sub(pos)
end

function switch(element)
    local Table = {
        ["Value"] = element,
        ["DefaultFunction"] = nil,
        ["Functions"] = {}
    }

    Table.case = function(testElement, callback)
        Table.Functions[testElement] = callback
        return Table
    end

    Table.default = function(callback)
        Table.DefaultFunction = callback
        return Table
    end

    Table.process = function()
        local Case = Table.Functions[Table.Value]
        if Case then
            Case()
        elseif Table.DefaultFunction then
            Table.DefaultFunction()
        end
    end

    return Table
end

-- Initialization callback
function on_init()
    -- Request the fields that we need
    ftype = chisel.request_field("evt.type")
    fdir = chisel.request_field("evt.dir")
    procname = chisel.request_field("proc.name")
    f_filetype = chisel.request_field("fd.type")
    filename = chisel.request_field("fd.name")
    f_fdvalue = chisel.request_field("fd.num")
    pid = chisel.request_field("proc.pid")
    ppid = chisel.request_field("proc.ppid")
    procname = chisel.request_field("proc.name")
    procargs = chisel.request_field("proc.cmdline")
    username = chisel.request_field("user.name")
    f_fd_ino = chisel.request_field("fd.ino")

    f_pipe2_ino = chisel.request_field("evt.arg.ino")
    f_pipe2_flags = chisel.request_field("evt.arg.flags")
    f_pipe2_fd1 = chisel.request_field("evt.rawarg.fd1")
    f_pipe2_fd2 = chisel.request_field("evt.rawarg.fd2")

    f_dup2_oldfd = chisel.request_field("evt.rawarg.oldfd")
    f_dup2_newfd = chisel.request_field("evt.rawarg.newfd")

    f_clone_pid = chisel.request_field("evt.rawarg.pid")
    f_clone_res = chisel.request_field("evt.rawarg.res")

    f_close_fd = chisel.request_field("evt.rawarg.fd")
    return true
end

count = 0

function on_call_openat()
    -- Print the initial value of the count
    print("Openat by " .. evt.field(procname))
    if evt.field(fdir) == "<" then
        print("\tFilename: " .. evt.field(filename))
    end
end

function log_read_or_write(op_type)
    if evt.field(fdir) == "<" then
        name = evt.field(filename)
        fd_value = evt.field(f_fdvalue)
        evt_pid = evt.field(pid)
        evt_ppid = evt.field(ppid)
        isapipe = false
        if evt.field(f_filetype) == "pipe" and (name == nil or name == "") then
            name = "/?/pipe/" .. evt.field(f_fd_ino)
            isapipe = true
        end
        if name == nil or name == "" then
            name = "unknown"
            return
        end
        if name:startswith("/dev/ptmx") then
            return
        end
        if not name:startswith("/") then
            return
        end
        -- print("Read by " .. evt.field(procname) .. ": " .. name)
        that_f_table = {
            ["name"] = name,
            ["pid"] = evt_pid,
            ["ppid"] = evt_ppid,
            ["type"] = op_type,
            ["username"] = evt.field(username),
            ["procname"] = evt.field(procname),
            ["procargs"] = evt.field(procargs),
            ["ispipe"] = isapipe,
            ["kind"] = "fd_rw"
        }
        -- io.stderr:write("read_or_write: " .. type(evt.field(procargs)) .. "\n")
        print(cbor.encode(that_f_table))
    end
end

function on_call_read()
    log_read_or_write("read")
end

function on_call_write()
    log_read_or_write("write")
end

function on_call_pipe2()
    if evt.field(fdir) == "<" then
        local fd1 = evt.field(f_pipe2_fd1)
        local fd2 = evt.field(f_pipe2_fd2)
        local ino = evt.field(f_pipe2_ino)
        local flags = evt.field(f_pipe2_flags)
        encoded_table = {
            ["fd1"] = fd1,
            ["fd2"] = fd2,
            ["ino"] = ino,
            ["flags"] = flags,
            ["pid"] = evt.field(pid),
            ["username"] = evt.field(username),
            ["kind"] = "pipe2"
        }
        print(cbor.encode(encoded_table))
        -- io.stderr:write("pipe2: fd1=" .. fd1 .. ", fd2=" .. fd2 .. ", ino=" .. ino .. ", flags=" .. flags .. ", pid=" .. evt.field(pid) .. "\n")
    end
end

function on_call_dup2()
    if evt.field(fdir) == "<" then
    end
end

function on_call_clone()
    if evt.field(fdir) == "<" then
        local res_value = evt.field(f_clone_res)
        if res_value == 0 then -- This is a successful clone, but from the child's perspective; we want the the child PID here
            return
        end
        local pid_value = evt.field(f_clone_pid)
        local final_table = {
            ["ppid"] = pid_value,
            ["pid"] = res_value,
            ["username"] = evt.field(username),
            ["kind"] = "clone"
        }
        print(cbor.encode(final_table))
    end
end

function on_call_close()
    if evt.field(fdir) == ">" then
        local fd_value = evt.field(f_close_fd)
        local evt_pid = evt.field(pid)
        local final_table = {
            ["fd"] = fd_value,
            ["pid"] = evt_pid,
            ["username"] = evt.field(username),
            ["kind"] = "close"
        }
        print(cbor.encode(final_table))
    end
end

function on_call_procexit()
    if evt.field(fdir) == ">" then
        local evt_pid = evt.field(pid)
        local final_table = {
            ["pid"] = evt_pid,
            ["username"] = evt.field(username),
            ["kind"] = "procexit"
        }
        print(cbor.encode(final_table))
    end
end

-- Event parsing callback
function on_event()
    -- if evt.field(ftype) == syscallname and evt.field(fdir) == ">" then
    -- 	count = count + 1
    -- 	print(count)
    -- end
    -- print("Event: '" .. evt.field(ftype) .. "'")
    switch(evt.field(ftype))
    -- .case("openat", on_call_openat)
        .case("read", on_call_read)
        .case("write", on_call_write)
        .case("pipe2", on_call_pipe2)
        .case("dup2", on_call_dup2)
        .case("clone", on_call_clone)
        .case("close", on_call_close)
    -- .default(function() print("Unknown syscall") end)
        .process()

    return true
end

-- Argument notification callback
function on_set_arg(name, val)
    print("set_arg: " .. name .. " = " .. val)
    syscallname = val
    return true
end
