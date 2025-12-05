/**
 * Font Size Control Widget
 * Provides increase/decrease font size controls with localStorage persistence
 */

class FontSizeControl {
    constructor(options = {}) {
        this.minSize = options.minSize || 12;
        this.maxSize = options.maxSize || 24;
        this.defaultSize = options.defaultSize || 16;
        this.step = options.step || 1;
        this.storageKey = options.storageKey || 'nmap_demo_font_size';
        this.targetSelector = options.targetSelector || 'body';
        
        this.currentSize = this.loadFontSize();
        this.init();
    }

    loadFontSize() {
        const saved = localStorage.getItem(this.storageKey);
        if (saved) {
            const size = parseInt(saved, 10);
            if (size >= this.minSize && size <= this.maxSize) {
                return size;
            }
        }
        return this.defaultSize;
    }

    saveFontSize(size) {
        localStorage.setItem(this.storageKey, size.toString());
    }

    applyFontSize(size) {
        const target = document.querySelector(this.targetSelector);
        if (target) {
            target.style.fontSize = `${size}px`;
            // Also apply to root for rem-based sizing
            document.documentElement.style.fontSize = `${size}px`;
        }
    }

    increase() {
        if (this.currentSize < this.maxSize) {
            this.currentSize = Math.min(this.currentSize + this.step, this.maxSize);
            this.applyFontSize(this.currentSize);
            this.saveFontSize(this.currentSize);
            this.updateDisplay();
        }
    }

    decrease() {
        if (this.currentSize > this.minSize) {
            this.currentSize = Math.max(this.currentSize - this.step, this.minSize);
            this.applyFontSize(this.currentSize);
            this.saveFontSize(this.currentSize);
            this.updateDisplay();
        }
    }

    updateDisplay() {
        if (this.sizeDisplay) {
            this.sizeDisplay.textContent = `${this.currentSize}px`;
        }
    }

    createWidget() {
        const widget = document.createElement('div');
        widget.className = 'font-size-control';
        widget.innerHTML = `
            <button class="font-btn decrease" aria-label="Decrease font size" title="Decrease font size">
                <span>−</span>
            </button>
            <span class="font-size-display">${this.currentSize}px</span>
            <button class="font-btn increase" aria-label="Increase font size" title="Increase font size">
                <span>+</span>
            </button>
        `;

        this.sizeDisplay = widget.querySelector('.font-size-display');
        
        const decreaseBtn = widget.querySelector('.decrease');
        const increaseBtn = widget.querySelector('.increase');

        decreaseBtn.addEventListener('click', () => this.decrease());
        increaseBtn.addEventListener('click', () => this.increase());

        return widget;
    }

    init() {
        // Apply saved font size on load
        this.applyFontSize(this.currentSize);
        
        // Create and insert widget
        const widget = this.createWidget();
        const container = document.querySelector('.font-size-control-container');
        if (container) {
            // Container exists (may be empty or have floating class)
            container.appendChild(widget);
        } else {
            // Fallback: try to find inner-navigation and append
            const innerNav = document.querySelector('.inner-navigation');
            if (innerNav) {
                const container = document.createElement('div');
                container.className = 'font-size-control-container';
                container.appendChild(widget);
                innerNav.appendChild(container);
            } else {
                // Last resort: create floating container
                const container = document.createElement('div');
                container.className = 'font-size-control-container floating';
                container.appendChild(widget);
                document.body.appendChild(container);
            }
        }
    }
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.fontSizeControl = new FontSizeControl();
    });
} else {
    window.fontSizeControl = new FontSizeControl();
}

