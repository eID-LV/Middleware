
app default {
	# debug = 0;
	# debug_file = "/tmp/latvia-eid.log";
	}
# Used by OpenSC.tokend on Mac OS X only.
app tokend {
        # The file to which debug log will be written
        # Default: /tmp/opensc-tokend.log
        #
        # debug_file = /tmp/OTLVID.tokend.log

        framework tokend {
                # Score for OpenSC.tokend
                # The tokend with the highest score shall be used.
                # Default: 300
                #
                score = 1000;
        }
}

