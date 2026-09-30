/**
 * WebSocket Streaming Service with Auto-Reconnect for SIH 2026 SOC Dashboard
 */

export class SOCWebSocketClient {
  constructor(url = "ws://127.0.0.1:8000/ws/stream") {
    this.url = url;
    this.ws = null;
    this.listeners = new Set();
    this.reconnectTimer = null;
    this.isConnected = false;
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        this.isConnected = true;
        this._notify({ type: "CONNECTION_STATUS", status: "CONNECTED" });
      };

      this.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          this._notify(payload);
        } catch (e) {
          console.error("WS Parse error", e);
        }
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        this._notify({ type: "CONNECTION_STATUS", status: "DISCONNECTED" });
        this._scheduleReconnect();
      };

      this.ws.onerror = (err) => {
        this.isConnected = false;
        this.ws?.close();
      };
    } catch (e) {
      this._scheduleReconnect();
    }
  }

  _scheduleReconnect() {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 2500);
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  _notify(data) {
    for (const listener of this.listeners) {
      try {
        listener(data);
      } catch (e) {
        console.error("Listener error", e);
      }
    }
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

export const socWebSocket = new SOCWebSocketClient();
