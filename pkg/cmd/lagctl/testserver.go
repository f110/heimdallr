package lagctl

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

func testServer() error {
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/env", func(w http.ResponseWriter, req *http.Request) {
		b, _ := httputil.DumpRequest(req, true)
		fmt.Println(string(b))

		w.Write(b)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(5 * time.Millisecond)
		io.WriteString(w, "It's working!")
	})
	http.HandleFunc("/ws", func(w http.ResponseWriter, req *http.Request) {
		upgrader := &websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}

		go func() {
			for {
				typ, buf, err := conn.ReadMessage()
				if err != nil {
					log.Print(err)
					return
				}
				log.Print(string(buf))

				if err := conn.WriteMessage(typ, buf); err != nil {
					log.Print(err)
					return
				}
			}
		}()
	})
	http.HandleFunc("/ws_client", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, `<!DOCTYPE html>
<html>
<head>
<script type="text/javascript">
window.onload = function () {
	conn = new WebSocket("wss://" + document.location.host + "/ws");
	conn.onmessage = function (evt) {
		console.log(evt);
	};
	setInterval(function() {conn.send("test")}, 1000);
};
</script>
</head>
<body>
</body>
</html>`)
	})
	fmt.Println("Listen :4501")
	return http.ListenAndServe(":4501", nil)
}

func TestServer(rootCmd *cobra.Command) {
	testServerCmd := &cobra.Command{
		Use:   "testserver",
		Short: "Start a http server for testing",
		RunE: func(_ *cobra.Command, _ []string) error {
			return testServer()
		},
	}

	rootCmd.AddCommand(testServerCmd)
}
