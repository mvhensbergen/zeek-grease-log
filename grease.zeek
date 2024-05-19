module GREASE;

export {
    redef enum Log::ID += { LOG };

    type GreaseInfo: record {
        ts: time &log;

        ## Unique ID for the connection.
		uid:                     string    &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                      conn_id   &log;

        # Amount of GREASE values in cipher lists
        grease_cipher_count: count &log &default=0;
        # Total amount of ciphers in cipher list
        total_cipher_count: count &log &default=0;

        # Amount of GREASE values in extension list
        grease_extension_count: count &log &default=0;
        # Total amount of extensions
        total_extension_count: count &log &default=0;

        # The indices of the extension that contains the GREASE value
        grease_extension_index: vector of count &log &default = vector();

        # Helper variable to keep track of current extension index
        grease_current_extension_index: count &default = 0;

        # The amount of GREASE values in named groups list
        grease_named_groups_count: count &log &default=0;
        # Total amount of named groups in list
        total_named_groups_count: count &log &default=0;

        # The amount of GREASE values in elliptic curves list
        grease_elliptic_curves_count: count &log &default=0;
        # Total amount of elliptic curves list
        total_elliptic_curves_count: count &log &default=0;

        # Name of the server to which is connected
        server_name: string &log;
    };
}


global grease_cipher_values :set[int] ={
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa};

redef record connection += {
	grease: GreaseInfo &optional;
};

function is_grease_value(p: int): bool {
    if (p in grease_cipher_values) {
        return T;
    }
    return F;
}

# Count the amount of (GREASE) ciphers
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=5
	{
        local p: int;
        local grease_count: count = 0;

        for ( index in ciphers) {
            p = ciphers[index];
            if ( is_grease_value(p)) {
                grease_count +=1;
            }
        }

        c$grease$server_name = c$ssl$server_name;
        c$grease$grease_cipher_count = grease_count;
        c$grease$total_cipher_count = |ciphers|;

        Log::write(GREASE::LOG, c$grease);
    }

function add_grease_section(c:connection) {
    if ( !c?$grease ) {
        local g : GreaseInfo;
        g$ts = network_time();
        g$id = c$id;
        g$uid = c$uid;
        c$grease = g;
    }
}

# Count the amount of (GREASE) extension values
event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
    add_grease_section(c);

	if ( is_orig )
		if (is_grease_value(code)) {
            c$grease$grease_extension_count += 1;
            c$grease$grease_extension_index[|c$grease$grease_extension_index|] = c$grease$grease_current_extension_index;
        }
        c$grease$grease_current_extension_index += 1;
        c$grease$total_extension_count += 1;
	}


# Count groups in key_share extension
event ssl_extension_key_share (c: connection, is_client: bool, curves: index_vec) {
    add_grease_section(c);

    if ( is_client ) {
        local p : count = 0;
        local key_share_count: count = 0;

        for (index in curves) {
            if (is_grease_value(curves[index])) {
                c$grease$grease_named_groups_count += 1;
            }
            c$grease$total_named_groups_count += 1;
        }

    }
}

# Count elliptic curves in elliptic_curves extension
event ssl_extension_elliptic_curves (c: connection, is_client: bool, curves: index_vec) {
    add_grease_section(c);

    if ( is_client ) {
        local p : count = 0;
        local key_share_count: count = 0;

        for (index in curves) {
            if (is_grease_value(curves[index])) {
                c$grease$grease_elliptic_curves_count += 1;
            }
            c$grease$total_elliptic_curves_count += 1;
        }

    }
}

event zeek_init() &priority=5
    {
    Log::create_stream(GREASE::LOG, [$columns=GreaseInfo, $path="grease"]);
    }