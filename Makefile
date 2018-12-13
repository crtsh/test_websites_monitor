all: clean test_websites_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f test_websites_monitor

test_websites_monitor:
	GOPATH=/home/rob/go go build test_websites_monitor.go processor_main.go
