/**
 * Utility functions for Shadow IT Discovery Bot
 */

const Utils = {
    /**
     * Format a timestamp to readable date/time
     */
    formatTimestamp(timestamp) {
        if (!timestamp) return '--';
        const date = new Date(timestamp);
        return date.toLocaleString();
    },

    /**
     * Truncate text with ellipsis
     */
    truncate(text, maxLength = 30) {
        if (!text || text.length <= maxLength) return text || '--';
        return text.substring(0, maxLength) + '...';
    },

    /**
     * Get risk level CSS class
     */
    getRiskClass(riskLevel) {
        const level = (riskLevel || '').toLowerCase();
        switch (level) {
            case 'critical': return 'risk-critical';
            case 'high': return 'risk-high';
            case 'medium': return 'risk-medium';
            case 'low': return 'risk-low';
            default: return 'risk-low';
        }
    },

    /**
     * Get priority dot CSS class
     */
    getPriorityClass(priority) {
        const p = (priority || '').toLowerCase();
        switch (p) {
            case 'critical': return 'priority-critical';
            case 'high': return 'priority-high';
            case 'medium': return 'priority-medium';
            default: return 'priority-low';
        }
    },

    /**
     * Get risk color for charts
     */
    getRiskColor(riskLevel) {
        const level = (riskLevel || '').toLowerCase();
        switch (level) {
            case 'critical': return '#ef4444';
            case 'high': return '#f97316';
            case 'medium': return '#eab308';
            case 'low': return '#22c55e';
            default: return '#6b7280';
        }
    },

    /**
     * Get posture rating text
     */
    getPostureRating(score) {
        if (score >= 80) return 'Excellent';
        if (score >= 60) return 'Good';
        if (score >= 40) return 'Fair';
        if (score >= 20) return 'Poor';
        return 'Critical';
    },

    /**
     * Get posture color
     */
    getPostureColor(score) {
        if (score >= 80) return '#22c55e';
        if (score >= 60) return '#84cc16';
        if (score >= 40) return '#eab308';
        if (score >= 20) return '#f97316';
        return '#ef4444';
    },

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    },

    /**
     * Show element
     */
    show(elementOrId) {
        const el = typeof elementOrId === 'string' 
            ? document.getElementById(elementOrId) 
            : elementOrId;
        if (el) el.classList.remove('hidden');
    },

    /**
     * Hide element
     */
    hide(elementOrId) {
        const el = typeof elementOrId === 'string' 
            ? document.getElementById(elementOrId) 
            : elementOrId;
        if (el) el.classList.add('hidden');
    },

    /**
     * Add fade-in animation
     */
    fadeIn(elementOrId) {
        const el = typeof elementOrId === 'string' 
            ? document.getElementById(elementOrId) 
            : elementOrId;
        if (el) {
            el.classList.remove('hidden');
            el.classList.add('fade-in');
        }
    },

    /**
     * Sleep/delay helper
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    /**
     * Generate unique ID
     */
    generateId() {
        return 'id_' + Math.random().toString(36).substr(2, 9);
    },

    /**
     * Count assets by risk level
     */
    countByRisk(assets) {
        const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        (assets || []).forEach(asset => {
            const level = (asset.risk_level || '').toLowerCase();
            if (counts.hasOwnProperty(level)) {
                counts[level]++;
            }
        });
        
        return counts;
    },

    /**
     * Debounce function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};

// Make Utils globally available
window.Utils = Utils;
