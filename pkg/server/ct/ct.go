package ct

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"

	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/server"
)

type Server struct{}

type ReportRequest struct {
	Report Report `json:"expect-ct-report"`
}

type Report struct {
	DateTime                  time.Time `json:"date-time"`
	Hostname                  string    `json:"hostname"`
	Port                      int       `json:"port"`
	Scheme                    string    `json:"scheme"`
	EffectiveExpirationDate   time.Time `json:"effective-expiration-date"`
	ServedCertificateChain    [][]byte  `json:"served-certificate-chain"`
	ValidatedCertificateChain [][]byte  `json:"validated-certificate-chain"`
	Scts                      []Sct     `json:"scts"`
	FailureMode               string    `json:"failure-mode"`
	TestReport                bool      `json:"test-report"`
}

type Sct struct {
	Version       int    `json:"version"`
	Status        string `json:"status"`
	Source        string `json:"source"`
	SerializedSct string `json:"serialized_sct"`
}

var _ server.ChildServer = &Server{}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Route(router *httprouter.Router) {
	router.OPTIONS("/ct/report", s.handleCORS)
	router.POST("/ct/report", s.handleReport)
}

func (s *Server) handleReport(w http.ResponseWriter, req *http.Request, _params httprouter.Params) {
	report := &ReportRequest{}
	if err := json.NewDecoder(req.Body).Decode(report); err != nil {
		logger.Log.Warn("Can not parse report body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logger.Log.Info("CT Report", zap.Any("report", report.Report))
}

func (s *Server) handleCORS(w http.ResponseWriter, req *http.Request, _params httprouter.Params) {
	logger.Log.Debug("options", zap.Any("req", req))
	w.Header().Set("Access-Control-Allow-Methods", req.Header.Get("Access-Control-Request-Method"))
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
}
