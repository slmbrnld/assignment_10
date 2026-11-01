
module ConnectScanDetect;

export {
    redef enum Notice::Type += {
        Connect_Scan
    };
}

const threshold: count = 10;

global scan_count: table[addr] of count
    &default=0;

global notice_count: table[addr] of count
    &default=0;

event connection_state_remove(c: connection)
{
    if (c$conn$proto == tcp)
    {
        if ("S" in c$conn$history &&
            "h" in c$conn$history &&
            "A" in c$conn$history)
        {
            scan_count[c$id$orig_h] += 1;

            if (scan_count[c$id$orig_h] >= threshold)
            {
                local n: Notice::Info = [
                    $note = Connect_Scan,
                    $src = c$id$orig_h,
                    $msg = fmt(
                        "Possible TCP Connect scan detected. Previous Notices: %d",
                        notice_count[c$id$orig_h]
                    )
                ];

                NOTICE(n);

                notice_count[c$id$orig_h] += 1;
                scan_count[c$id$orig_h] = 0;
            }
        }
    }
}
