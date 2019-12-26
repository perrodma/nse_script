local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Check for existance of security.txt on the webserver.
]]

---
----@output
--80/tcp open http syn-ack
-- | security.txt : Found
-- | # If you would like to report a security issue
-- | # you may report it to us on HackerOne.
-- | Contact: https://hackerone.com/ed
-- | Encryption: https://keybase.pub/edoverflow/pgp_key.asc
-- | Acknowledgements: https://hackerone.com/ed/thanks

author = "Perrod Matthias"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http


action = function(host, port)
  local ans = http.get(host, port, "/.well-known/security.txt")
  stdnse.verbose("Get response code :" .. ans.status)
  if ans.status ~= 200 then
    return nil
  end

  local out = "\n" .. ans.body
  return out
end
