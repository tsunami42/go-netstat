package netstat

import (
	"fmt"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	ip := "0100007F"
	fmt.Println(ip)
	result, err := parseIPv4(ip)
	fmt.Printf("%v %v", result, err)
}

func Test_extraceSocketInode(t *testing.T) {
	type args struct {
		socketStr string
	}
	tests := []struct {
		name      string
		args      args
		wantInode string
	}{
		{
			name: "success",
			args: args{
				socketStr: "socket:[14943]",
			},
			wantInode: "14943",
		},
		{
			name: "fail",
			args: args{
				socketStr: "/var/log/nginx/error.log",
			},
			wantInode: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotInode := extraceSocketInode(tt.args.socketStr); gotInode != tt.wantInode {
				t.Errorf("extraceSocketInode() = %v, want %v", gotInode, tt.wantInode)
			}
		})
	}
}
