package gnmidriver

import (
	"context"
	"crypto/tls"
	"log"
	"strconv"
	"sync"

	"github.com/openconfig/gnmi/client"
	cli "github.com/openconfig/gnmi/client/gnmi"
	"github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	gnmiClient  client.Impl
	defaultAddr = "0.0.0.0:9339"
	GnmiConn    *grpc.ClientConn
	once        sync.Once
)

type RuleSet struct {
	Rule map[string]interface{} `json:"rule"`
}

func NewgNMIClient(ctx context.Context) error {
	once.Do(func() {
		conn, err := grpc.Dial(defaultAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalf("intel-e2000: Cannot connect to server: %v\n", err)
		}
		var err1 error
		/*ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()*/
		/*gnmiClient, err = client.NewImpl(ctx, client.Destination{
			Addrs: []string{targetAddr},
		}, "gnmi")
		if err != nil {
			log.Fatalf("Failed to initialize gNMI client: %v", err)
			return err
		}*/
		/*gnmiClient, err = cli.New(ctx, client.Destination{
			Addrs: []string{targetAddr},
			TLS:   &tls.Config{InsecureSkipVerify: true},
		})*/

		gnmiClient, err1 = cli.NewFromConn(ctx, conn, client.Destination{
			Addrs: []string{defaultAddr},
			TLS:   &tls.Config{InsecureSkipVerify: true},
		})
		if err1 != nil {
			log.Fatalf("Failed to initialize gNMI client: %v", err)
		}
		log.Printf("gnmi cli sucsessful\n")
	})
	return nil
}

func Set(ctx context.Context, offloadID int, direction bool, value *gnmi.TypedValue) (*gnmi.SetResponse, error) {
	clientImpl, _ := gnmiClient.(*cli.Client)
	offloadIDStr := strconv.Itoa(offloadID)
	directionStr := strconv.FormatBool(direction)
	request := &gnmi.SetRequest{
		Update: []*gnmi.Update{
			{
				Path: &gnmi.Path{
					Elem: []*gnmi.PathElem{{Name: "ipsec-offload"}, {Name: "sad"}, {Name: "sad-entry", Key: map[string]string{"offload-id": offloadIDStr, "direction": directionStr}}, {Name: "config"}},
				},
				Val: value,
			},
		},
	}
	response, err := clientImpl.Set(ctx, request)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func Del(ctx context.Context, offloadID int, direction bool) (*gnmi.SetResponse, error) {
	clientImpl, _ := gnmiClient.(*cli.Client)
	offloadIDStr := strconv.Itoa(offloadID)
	directionStr := strconv.FormatBool(direction)
	request := &gnmi.SetRequest{
		Delete: []*gnmi.Path{
			{
				Elem: []*gnmi.PathElem{{Name: "ipsec-offload"}, {Name: "sad"}, {Name: "sad-entry", Key: map[string]string{"offload-id": offloadIDStr, "direction": directionStr}}, {Name: "config"}},
			},
		},
	}
	response, err := clientImpl.Set(ctx, request)
	if err != nil {
		return nil, err
	}

	return response, nil
}
