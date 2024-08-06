all: clean test_websites_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f test_websites_monitor

test_websites_monitor:
	go build -ldflags "-X main.build_date=`date -u +%Y-%m-%d.%H:%M:%S`" test_websites_monitor.go processor_main.go
