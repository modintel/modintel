var SSE = (function () {
    var MAX_RETRIES = 3;

    function SSEClient(url, handlers) {
        this.url = url;
        this.handlers = handlers;
        this.es = null;
        this.retryCount = 0;
        this.active = false;
        this.fallbackActive = false;
        this.indicator = null;
    }

    SSEClient.prototype.connect = function () {
        var self = this;

        this.es = new EventSource(this.url);

        this.es.onopen = function () {
            self.retryCount = 0;
            self.active = true;
            self.setState('connected');
            if (self.handlers.onConnect) self.handlers.onConnect();
        };

        this.es.onerror = function () {
            if (self.es.readyState === EventSource.CLOSED) {
                self.active = false;
                self.retryCount++;
                if (self.retryCount >= MAX_RETRIES) {
                    self.setState('disconnected');
                    if (self.handlers.onFallback) {
                        self.fallbackActive = true;
                        self.handlers.onFallback();
                    }
                } else {
                    self.setState('reconnecting');
                }
            }
        };

        this.attachListener('alert', this.handlers.onAlert);
        this.attachListener('stats', this.handlers.onStats);
        this.attachListener('metrics', this.handlers.onMetrics);
        this.attachListener('health', this.handlers.onHealth);
    };

    SSEClient.prototype.attachListener = function (type, handler) {
        if (!handler || !this.es) return;
        this.es.addEventListener(type, function (e) {
            try {
                var data = JSON.parse(e.data);
                handler(data);
            } catch (err) {
                console.error('SSE parse error for ' + type + ':', err);
            }
        });
    };

    SSEClient.prototype.close = function () {
        if (this.es) {
            this.es.close();
            this.es = null;
        }
        this.active = false;
    };

    SSEClient.prototype.setState = function (state) {
        if (this.indicator) {
            var dot = this.indicator.querySelector('.connection-dot');
            var label = this.indicator.querySelector('.connection-label');
            if (dot) {
                dot.className = 'connection-dot ' + state;
            }
            if (label) {
                switch (state) {
                    case 'connected':
                        label.textContent = 'Live';
                        break;
                    case 'reconnecting':
                        label.textContent = 'Reconnecting';
                        break;
                    case 'disconnected':
                        label.textContent = 'Disconnected';
                        break;
                    case 'fallback':
                        label.textContent = 'Polling';
                        break;
                }
            }
        }
        if (this.handlers.onStateChange) {
            this.handlers.onStateChange(state);
        }
    };

    function createConnectionIndicator(elementId) {
        var el = document.getElementById(elementId);
        if (!el) return null;
        el.innerHTML = '<span class="connection-indicator">' +
            '<span class="connection-dot reconnecting"></span>' +
            '<span class="connection-label">Connecting...</span>' +
            '</span>';
        return el.querySelector('.connection-indicator');
    }

    window.SSEClient = SSEClient;
    window.SSE_createIndicator = createConnectionIndicator;

    return { SSEClient: SSEClient, createIndicator: createConnectionIndicator };
})();
