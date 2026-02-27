/**
 * Chart.js configurations for Shadow IT Discovery Bot
 */

const Charts = {
    // Chart instances
    _severityChart: null,
    _postureGauge: null,

    /**
     * Initialize or update severity distribution chart
     * @param {Object} riskCounts - {critical, high, medium, low}
     */
    updateSeverityChart(riskCounts) {
        const ctx = document.getElementById('severity-chart');
        if (!ctx) return;

        const data = {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    riskCounts.critical || 0,
                    riskCounts.high || 0,
                    riskCounts.medium || 0,
                    riskCounts.low || 0
                ],
                backgroundColor: [
                    '#ef4444',
                    '#f97316',
                    '#eab308',
                    '#22c55e'
                ],
                borderColor: 'transparent',
                borderWidth: 0,
                hoverOffset: 4
            }]
        };

        const options = {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#9ca3af',
                        font: {
                            size: 11
                        },
                        padding: 12,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: '#1f2937',
                    titleColor: '#f3f4f6',
                    bodyColor: '#d1d5db',
                    borderColor: '#374151',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: true,
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 
                                ? Math.round((context.raw / total) * 100) 
                                : 0;
                            return `${context.raw} assets (${percentage}%)`;
                        }
                    }
                }
            }
        };

        // Destroy existing chart if exists
        if (this._severityChart) {
            this._severityChart.destroy();
        }

        // Create new chart
        this._severityChart = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: options
        });
    },

    /**
     * Initialize or update posture gauge
     * @param {number} score - Posture score (0-100)
     */
    updatePostureGauge(score) {
        const ctx = document.getElementById('posture-gauge');
        if (!ctx) return;

        const normalizedScore = Math.max(0, Math.min(100, score || 0));
        const color = Utils.getPostureColor(normalizedScore);

        const data = {
            datasets: [{
                data: [normalizedScore, 100 - normalizedScore],
                backgroundColor: [color, '#1f2937'],
                borderWidth: 0,
                circumference: 270,
                rotation: 225
            }]
        };

        const options = {
            responsive: true,
            maintainAspectRatio: true,
            cutout: '75%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        };

        // Destroy existing chart if exists
        if (this._postureGauge) {
            this._postureGauge.destroy();
        }

        // Create new chart
        this._postureGauge = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: options
        });

        // Update score display
        const scoreEl = document.getElementById('posture-score');
        const ratingEl = document.getElementById('posture-rating');
        const summaryEl = document.getElementById('posture-summary');

        if (scoreEl) scoreEl.textContent = normalizedScore;
        if (ratingEl) ratingEl.textContent = Utils.getPostureRating(normalizedScore);
        if (summaryEl) {
            if (normalizedScore >= 80) {
                summaryEl.textContent = 'Your security posture is strong';
            } else if (normalizedScore >= 60) {
                summaryEl.textContent = 'Some improvements recommended';
            } else if (normalizedScore >= 40) {
                summaryEl.textContent = 'Several risks need attention';
            } else {
                summaryEl.textContent = 'Critical issues require immediate action';
            }
        }
    },

    /**
     * Reset all charts to empty state
     */
    reset() {
        this.updateSeverityChart({ critical: 0, high: 0, medium: 0, low: 0 });
        this.updatePostureGauge(0);
    },

    /**
     * Destroy all charts
     */
    destroy() {
        if (this._severityChart) {
            this._severityChart.destroy();
            this._severityChart = null;
        }
        if (this._postureGauge) {
            this._postureGauge.destroy();
            this._postureGauge = null;
        }
    }
};

// Make Charts globally available
window.Charts = Charts;
