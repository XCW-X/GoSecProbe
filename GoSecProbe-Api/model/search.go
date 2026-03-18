package model

// SearchResult represents a normalized search-engine result.
type SearchResult struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Location string `json:"location"`
	Title    string `json:"title"`
	ICP      string `json:"icp"`
}
