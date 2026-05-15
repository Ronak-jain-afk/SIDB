/**
 * Main application logic for Shadow IT Discovery Bot
 */

const App = {   
    // Current state
    state: {
        scanning: false,
        currentScanId: null,
        results: null,
        dashboard: null,
        filteredAssets: []
    },

    // DOM elements cache
    elements: {},

    /**
     * Initialize application
     */
    init() {
        // Cache DOM elements
        this.cacheElements();
        
        // Bind event handlers
        this.bindEvents();
        
        // Show initial state
        this.showEmptyState();
        
        console.log('Shadow IT Discovery Bot initialized');
    },

    /**
     * Cache DOM elements for performance
     */
    cacheElements() {
        this.elements = {
            scanForm: document.getElementById('scan-form'),
            domainInput: document.getElementById('domain-input'),
            networkScanToggle: document.getElementById('network-scan-toggle'),
            scanButton: document.getElementById('scan-button'),
            progressSection: document.getElementById('progress-section'),
            progressBar: document.getElementById('progress-bar'),
            progressText: document.getElementById('progress-text'),
            progressStatus: document.getElementById('progress-status'),
            dashboardContent: document.getElementById('dashboard-content'),
            emptyState: document.getElementById('empty-state'),
            errorState: document.getElementById('error-state'),
            errorMessage: document.getElementById('error-message'),
            retryButton: document.getElementById('retry-button'),
            assetsTableBody: document.getElementById('assets-table-body'),
            noAssets: document.getElementById('no-assets'),
            recommendationsContainer: document.getElementById('recommendations-container'),
            noRecommendations: document.getElementById('no-recommendations'),
            riskFilter: document.getElementById('risk-filter'),
            statTotal: document.getElementById('stat-total'),
            statCritical: document.getElementById('stat-critical'),
            statHigh: document.getElementById('stat-high'),
            statMedium: document.getElementById('stat-medium')
        };
    },

    /**
     * Bind event handlers
     */
    bindEvents() {
        // Scan form submission
        this.elements.scanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.startScan();
        });

        // Retry button
        this.elements.retryButton.addEventListener('click', () => {
            this.showEmptyState();
        });

        // Risk filter
        this.elements.riskFilter.addEventListener('change', () => {
            this.filterAssets();
        });
    },

    /**
     * Show empty state
     */
    showEmptyState() {
        Utils.hide(this.elements.progressSection);
        Utils.hide(this.elements.dashboardContent);
        Utils.hide(this.elements.errorState);
        Utils.show(this.elements.emptyState);
        
        // Reset form
        this.elements.domainInput.value = '';
        this.elements.domainInput.disabled = false;
        this.elements.scanButton.disabled = false;
        this.elements.scanButton.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
            <span>Scan</span>
        `;
    },

    /**
     * Show scanning progress
     */
    showProgress() {
        Utils.hide(this.elements.emptyState);
        Utils.hide(this.elements.dashboardContent);
        Utils.hide(this.elements.errorState);
        Utils.show(this.elements.progressSection);
        
        // Disable form
        this.elements.domainInput.disabled = true;
        this.elements.scanButton.disabled = true;
        this.elements.scanButton.innerHTML = `
            <div class="btn-spinner"></div>
            <span>Scanning...</span>
        `;
    },

    /**
     * Show dashboard
     */
    showDashboard() {
        Utils.hide(this.elements.emptyState);
        Utils.hide(this.elements.progressSection);
        Utils.hide(this.elements.errorState);
        Utils.fadeIn(this.elements.dashboardContent);
        
        // Re-enable form
        this.elements.domainInput.disabled = false;
        this.elements.scanButton.disabled = false;
        this.elements.scanButton.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
            <span>Scan</span>
        `;
    },

    /**
     * Show error state
     * @param {string} message - Error message
     */
    showError(message) {
        Utils.hide(this.elements.emptyState);
        Utils.hide(this.elements.progressSection);
        Utils.hide(this.elements.dashboardContent);
        Utils.show(this.elements.errorState);
        
        this.elements.errorMessage.textContent = message;
        
        // Re-enable form
        this.elements.domainInput.disabled = false;
        this.elements.scanButton.disabled = false;
        this.elements.scanButton.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
            <span>Scan</span>
        `;
    },

    /**
     * Update progress bar
     * @param {Object} status - Status object with progress and status
     */
    updateProgress(status) {
        const statusText = status.status || 'pending';
        
        const progressMap = {
            'pending': 5,
            'scanning': 40,
            'analyzing': 70,
            'completed': 100,
            'failed': 100
        };
        const progress = progressMap[statusText] || 0;
        this.elements.progressBar.style.width = `${progress}%`;
        
        const textMap = {
            'pending': 'Initializing scan...',
            'scanning': 'Discovering assets...',
            'analyzing': 'Analyzing risks and generating recommendations...',
            'completed': 'Scan completed!',
            'failed': 'Scan failed'
        };
        this.elements.progressText.textContent = textMap[statusText] || 'Unknown';
        
        this.elements.progressStatus.textContent = statusText.toUpperCase();
        this.elements.progressStatus.className = 'text-xs px-2 py-1 rounded';
        if (statusText === 'completed') {
            this.elements.progressStatus.classList.add('bg-green-900/50', 'text-green-400');
        } else if (statusText === 'failed') {
            this.elements.progressStatus.classList.add('bg-red-900/50', 'text-red-400');
        } else if (statusText === 'scanning' || statusText === 'analyzing') {
            this.elements.progressStatus.classList.add('bg-cyan-900/50', 'text-cyan-400');
        } else {
            this.elements.progressStatus.classList.add('bg-gray-700', 'text-gray-300');
        }
    },

    /**
     * Start a new scan
     */
    async startScan() {
        const domain = this.elements.domainInput.value.trim();
        if (!domain) {
            alert('Please enter a domain');
            return;
        }

        const enableNetworkScan = this.elements.networkScanToggle.checked;

        this.state.scanning = true;
        this.showProgress();
        this.updateProgress({ status: 'pending', progress: 5 });

        try {
            // Run scan workflow
            const { results, dashboard, scanId } = await API.runScanWorkflow(
                domain,
                enableNetworkScan,
                (status) => this.updateProgress(status)
            );

            // Store results
            this.state.currentScanId = scanId;
            this.state.results = results;
            this.state.dashboard = dashboard;

            // Render dashboard
            this.renderDashboard();
            this.showDashboard();

        } catch (error) {
            console.error('Scan failed:', error);
            this.showError(error.message || 'An error occurred during the scan');
        } finally {
            this.state.scanning = false;
        }
    },

    /**
     * Render dashboard with results
     */
    renderDashboard() {
        const { results, dashboard } = this.state;
        const assets = results?.assets || [];

        // Update stats
        const riskCounts = Utils.countByRisk(assets);
        this.elements.statTotal.textContent = assets.length;
        this.elements.statCritical.textContent = riskCounts.critical;
        this.elements.statHigh.textContent = riskCounts.high;
        this.elements.statMedium.textContent = riskCounts.medium;

        // Update charts
        Charts.updateSeverityChart(riskCounts);
        Charts.updatePostureGauge(dashboard?.posture_score?.score || 0);

        // Render assets table
        this.state.filteredAssets = assets;
        this.renderAssetsTable(assets);

        // Render recommendations
        this.renderRecommendations(results?.recommendations || []);
    },

    /**
     * Render assets table
     * @param {Array} assets - Assets to render
     */
    renderAssetsTable(assets) {
        if (!assets || assets.length === 0) {
            this.elements.assetsTableBody.innerHTML = '';
            Utils.show(this.elements.noAssets);
            return;
        }

        Utils.hide(this.elements.noAssets);

        const rows = assets.map(asset => `
            <tr class="fade-in">
                <td class="px-4 py-3 whitespace-nowrap">
                    <span class="text-sm font-mono text-gray-300">${Utils.escapeHtml(Utils.truncate(asset.asset_id, 20))}</span>
                </td>
                <td class="px-4 py-3 whitespace-nowrap">
                    <span class="text-sm text-white">${Utils.escapeHtml(asset.ip || '--')}</span>
                </td>
                <td class="px-4 py-3 whitespace-nowrap">
                    <span class="text-sm text-gray-400">${asset.port || '--'}</span>
                </td>
                <td class="px-4 py-3 whitespace-nowrap">
                    <span class="text-sm text-gray-300">${Utils.escapeHtml(asset.service || '--')}</span>
                </td>
                <td class="px-4 py-3 whitespace-nowrap">
                    <span class="text-sm text-gray-300">${Utils.escapeHtml(Utils.truncate(asset.technology, 25))}</span>
                </td>
                <td class="px-4 py-3 whitespace-nowrap">
                    <span class="risk-badge ${Utils.getRiskClass(asset.risk_level)}">${Utils.escapeHtml(asset.risk_level || 'Unknown')}</span>
                </td>
                <td class="px-4 py-3 whitespace-nowrap">
                    <span class="text-sm font-medium ${asset.risk_score >= 70 ? 'text-red-400' : asset.risk_score >= 40 ? 'text-yellow-400' : 'text-green-400'}">
                        ${asset.risk_score || 0}
                    </span>
                </td>
            </tr>
        `).join('');

        this.elements.assetsTableBody.innerHTML = rows;
    },

    /**
     * Filter assets by risk level
     */
    filterAssets() {
        const filterValue = this.elements.riskFilter.value;
        const assets = this.state.results?.assets || [];

        if (filterValue === 'all') {
            this.state.filteredAssets = assets;
        } else {
            this.state.filteredAssets = assets.filter(
                asset => (asset.risk_level || '').toLowerCase() === filterValue.toLowerCase()
            );
        }

        this.renderAssetsTable(this.state.filteredAssets);
    },

    /**
     * Render recommendations
     * @param {Array} recommendations - Recommendations to render
     */
    renderRecommendations(recommendations) {
        if (!recommendations || recommendations.length === 0) {
            this.elements.recommendationsContainer.innerHTML = '';
            Utils.show(this.elements.noRecommendations);
            return;
        }

        Utils.hide(this.elements.noRecommendations);

        // Sort by priority (critical > high > medium > low)
        const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        const sorted = [...recommendations].sort((a, b) => 
            (priorityOrder[a.priority?.toLowerCase()] || 4) - (priorityOrder[b.priority?.toLowerCase()] || 4)
        );

        const items = sorted.map((rec, index) => {
            const id = `rec-${index}`;
            return `
                <div class="recommendation-item p-4" data-rec-id="${id}">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <span class="priority-dot ${Utils.getPriorityClass(rec.priority)}"></span>
                            <h4 class="font-medium text-white">${Utils.escapeHtml(rec.title || 'Recommendation')}</h4>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="text-xs px-2 py-1 bg-gray-700 rounded text-gray-300">${Utils.escapeHtml(rec.category || 'General')}</span>
                            <svg class="rec-chevron w-5 h-5 text-gray-500 transform transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                            </svg>
                        </div>
                    </div>
                    <div class="recommendation-content" id="${id}">
                        <div class="mt-4 pt-4 border-t border-cyber-border">
                            <p class="text-sm text-gray-400 mb-3">${Utils.escapeHtml(rec.description || '')}</p>
                            ${rec.remediation ? `
                                <div class="bg-gray-800/50 rounded-lg p-3">
                                    <h5 class="text-xs font-medium text-gray-400 uppercase mb-2">Remediation Steps</h5>
                                    <p class="text-sm text-gray-300">${Utils.escapeHtml(rec.remediation)}</p>
                                </div>
                            ` : ''}
                            ${rec.affected_assets && rec.affected_assets.length > 0 ? `
                                <div class="mt-3">
                                    <h5 class="text-xs font-medium text-gray-400 uppercase mb-2">Affected Assets</h5>
                                    <div class="flex flex-wrap gap-2">
                                        ${rec.affected_assets.slice(0, 5).map(asset => `
                                            <span class="text-xs px-2 py-1 bg-gray-700 rounded font-mono text-gray-300">${Utils.escapeHtml(Utils.truncate(asset, 20))}</span>
                                        `).join('')}
                                        ${rec.affected_assets.length > 5 ? `
                                            <span class="text-xs px-2 py-1 bg-gray-700 rounded text-gray-400">+${rec.affected_assets.length - 5} more</span>
                                        ` : ''}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        this.elements.recommendationsContainer.innerHTML = items;

        // Bind click handlers for accordion
        document.querySelectorAll('.recommendation-item').forEach(item => {
            item.addEventListener('click', () => {
                const recId = item.getAttribute('data-rec-id');
                const content = document.getElementById(recId);
                const chevron = item.querySelector('.rec-chevron');
                
                if (content.classList.contains('open')) {
                    content.classList.remove('open');
                    chevron.classList.remove('rotate-180');
                } else {
                    content.classList.add('open');
                    chevron.classList.add('rotate-180');
                }
            });
        });
    }
};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    App.init();
});

// Make App globally available for debugging
window.App = App;
