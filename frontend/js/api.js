/**
 * API client for Shadow IT Discovery Bot backend
 */

const API = {
    // Backend URL - adjust port if needed
    BASE_URL: 'http://localhost:8000/api',
    WS_BASE: 'ws://localhost:8000',
    
    // Poll interval for scan status (ms)
    POLL_INTERVAL: 2000,

    /**
     * Start a new scan
     * @param {string} domain - Domain to scan
     * @param {boolean} enableNetworkScan - Whether to enable network scanning
     * @returns {Promise<{scan_id: string, status: string}>}
     */
    async startScan(domain, enableNetworkScan = false) {
        const response = await fetch(`${this.BASE_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                domain: domain,
                enable_network_scan: enableNetworkScan
            }),
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `Failed to start scan: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Get scan status
     * @param {string} scanId - Scan ID to check
     * @returns {Promise<{status: string, progress: number}>}
     */
    async getStatus(scanId) {
        const response = await fetch(`${this.BASE_URL}/scan/${scanId}/status`);

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `Failed to get status: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Get scan results
     * @param {string} scanId - Scan ID to get results for
     * @returns {Promise<Object>}
     */
    async getResults(scanId) {
        const response = await fetch(`${this.BASE_URL}/results/${scanId}`);

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `Failed to get results: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Get dashboard summary
     * @param {string} scanId - Scan ID for dashboard
     * @returns {Promise<Object>}
     */
    async getDashboard(scanId) {
        const response = await fetch(`${this.BASE_URL}/dashboard/${scanId}`);

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `Failed to get dashboard: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Poll scan status until completion or failure
     * @param {string} scanId - Scan ID to poll
     * @param {function} onProgress - Callback for progress updates
     * @returns {Promise<Object>} - Final status object
     */
    async pollUntilComplete(scanId, onProgress) {
        let lastStatus = null;
        
        while (true) {
            try {
                const status = await this.getStatus(scanId);
                
                // Notify progress callback
                if (onProgress) {
                    onProgress(status);
                }
                
                // Check if scan is complete
                if (status.status === 'completed') {
                    return status;
                }
                
                // Check if scan failed
                if (status.status === 'failed') {
                    throw new Error(status.error || 'Scan failed');
                }
                
                lastStatus = status;
                
                // Wait before next poll
                await Utils.sleep(this.POLL_INTERVAL);
                
            } catch (error) {
                // If it's a network error and we have a last status, retry
                if (lastStatus && error.message.includes('fetch')) {
                    console.warn('Network error during poll, retrying...');
                    await Utils.sleep(this.POLL_INTERVAL * 2);
                    continue;
                }
                throw error;
            }
        }
    },

    /**
     * Watch scan progress via WebSocket (fallback to polling)
     * @param {string} scanId - Scan ID to watch
     * @param {function} onProgress - Progress callback
     * @returns {Promise<void>}
     */
    watchScanViaWS(scanId, onProgress) {
        return new Promise((resolve, reject) => {
            let ws = null;
            let polling = false;
            let pollingTimer = null;

            const startPolling = () => {
                polling = true;
                const poll = async () => {
                    try {
                        while (polling) {
                            const status = await this.getStatus(scanId);
                            if (onProgress) onProgress(status);
                            if (status.status === 'completed') return resolve(status);
                            if (status.status === 'failed') return reject(new Error(status.error || 'Scan failed'));
                            await Utils.sleep(this.POLL_INTERVAL);
                        }
                    } catch (err) {
                        reject(err);
                    }
                };
                poll();
            };

            try {
                ws = new WebSocket(`${this.WS_BASE}/api/ws/scan/${scanId}`);

                ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        if (data.type === 'pong') return;
                        if (onProgress) onProgress(data);
                        if (data.status === 'completed') {
                            ws.close();
                            return resolve(data);
                        }
                        if (data.status === 'failed') {
                            ws.close();
                            return reject(new Error(data.message || 'Scan failed'));
                        }
                    } catch (e) {
                        console.warn('WS parse error, falling back to polling', e);
                        if (ws) ws.close();
                        startPolling();
                    }
                };

                ws.onerror = () => {
                    console.warn('WebSocket error, falling back to polling');
                    if (ws) ws.close();
                    startPolling();
                };

                ws.onclose = () => {
                    if (!polling) startPolling();
                };

                // Keepalive ping every 10s
                const keepalive = setInterval(() => {
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send('ping');
                    } else {
                        clearInterval(keepalive);
                    }
                }, 10000);

            } catch (e) {
                console.warn('WebSocket not available, using polling', e);
                startPolling();
            }
        });
    },

    /**
     * Compare two scans
     * @param {string} scanId1 - First scan ID
     * @param {string} scanId2 - Second scan ID
     * @returns {Promise<Object>}
     */
    async compareScans(scanId1, scanId2) {
        const response = await fetch(`${this.BASE_URL}/compare/${scanId1}/${scanId2}`);
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `Failed to compare scans: ${response.status}`);
        }
        return response.json();
    },

    /**
     * Run complete scan workflow
     * @param {string} domain - Domain to scan
     * @param {boolean} enableNetworkScan - Whether to enable network scanning
     * @param {function} onProgress - Progress callback
     * @returns {Promise<{results: Object, dashboard: Object}>}
     */
    async runScanWorkflow(domain, enableNetworkScan, onProgress) {
        // Start scan
        const scanResponse = await this.startScan(domain, enableNetworkScan);
        const scanId = scanResponse.scan_id;

        try {
            // Try WebSocket first, fallback to polling
            await this.watchScanViaWS(scanId, onProgress);
        } catch (err) {
            // If WebSocket fails, use polling
            await this.pollUntilComplete(scanId, onProgress);
        }

        // Fetch results and dashboard in parallel
        const [results, dashboard] = await Promise.all([
            this.getResults(scanId),
            this.getDashboard(scanId)
        ]);

        return { results, dashboard, scanId };
    }
};

// Make API globally available
window.API = API;
