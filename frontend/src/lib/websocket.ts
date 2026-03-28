/**
 * WebSocket client for real-time NIDS event and metrics streaming
 */

type EventCallback = (data: any) => void;
type MetricsCallback = (data: any) => void;
type ConnectionCallback = (connected: boolean) => void;

class NIDSWebSocket {
  private eventsWs: WebSocket | null = null;
  private metricsWs: WebSocket | null = null;
  private eventCallbacks: EventCallback[] = [];
  private metricsCallbacks: MetricsCallback[] = [];
  private connectionCallbacks: ConnectionCallback[] = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000;
  private baseUrl: string;

  constructor() {
    // Use relative URLs for WebSocket - nginx will proxy them
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host; // includes port
    this.baseUrl = `${protocol}//${host}`;
  }

  connect() {
    this.connectEvents();
    this.connectMetrics();
  }

  private connectEvents() {
    if (this.eventsWs?.readyState === WebSocket.OPEN) return;

    try {
      this.eventsWs = new WebSocket(`${this.baseUrl}/ws/events`);

      this.eventsWs.onopen = () => {
        console.log('[WS] Events connected');
        this.reconnectAttempts = 0;
        this.notifyConnection(true);
      };

      this.eventsWs.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'event' || data.type === 'alert') {
            this.eventCallbacks.forEach(cb => cb(data));
          }
        } catch (e) {
          console.error('[WS] Failed to parse event:', e);
        }
      };

      this.eventsWs.onclose = () => {
        console.log('[WS] Events disconnected');
        this.notifyConnection(false);
        this.scheduleReconnect('events');
      };

      this.eventsWs.onerror = (error) => {
        console.error('[WS] Events error:', error);
      };
    } catch (e) {
      console.error('[WS] Failed to connect events:', e);
      this.scheduleReconnect('events');
    }
  }

  private connectMetrics() {
    if (this.metricsWs?.readyState === WebSocket.OPEN) return;

    try {
      this.metricsWs = new WebSocket(`${this.baseUrl}/ws/metrics`);

      this.metricsWs.onopen = () => {
        console.log('[WS] Metrics connected');
      };

      this.metricsWs.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'metrics') {
            this.metricsCallbacks.forEach(cb => cb(data));
          }
        } catch (e) {
          console.error('[WS] Failed to parse metrics:', e);
        }
      };

      this.metricsWs.onclose = () => {
        console.log('[WS] Metrics disconnected');
        this.scheduleReconnect('metrics');
      };

      this.metricsWs.onerror = (error) => {
        console.error('[WS] Metrics error:', error);
      };
    } catch (e) {
      console.error('[WS] Failed to connect metrics:', e);
      this.scheduleReconnect('metrics');
    }
  }

  private scheduleReconnect(type: 'events' | 'metrics') {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('[WS] Max reconnect attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    
    setTimeout(() => {
      console.log(`[WS] Reconnecting ${type} (attempt ${this.reconnectAttempts})`);
      if (type === 'events') {
        this.connectEvents();
      } else {
        this.connectMetrics();
      }
    }, delay);
  }

  private notifyConnection(connected: boolean) {
    this.connectionCallbacks.forEach(cb => cb(connected));
  }

  onEvent(callback: EventCallback) {
    this.eventCallbacks.push(callback);
    return () => {
      this.eventCallbacks = this.eventCallbacks.filter(cb => cb !== callback);
    };
  }

  onMetrics(callback: MetricsCallback) {
    this.metricsCallbacks.push(callback);
    return () => {
      this.metricsCallbacks = this.metricsCallbacks.filter(cb => cb !== callback);
    };
  }

  onConnectionChange(callback: ConnectionCallback) {
    this.connectionCallbacks.push(callback);
    // Immediately notify of current connection state
    callback(this.isConnected());
    return () => {
      this.connectionCallbacks = this.connectionCallbacks.filter(cb => cb !== callback);
    };
  }

  disconnect() {
    if (this.eventsWs) {
      this.eventsWs.close();
      this.eventsWs = null;
    }
    if (this.metricsWs) {
      this.metricsWs.close();
      this.metricsWs = null;
    }
  }

  isConnected(): boolean {
    return this.eventsWs?.readyState === WebSocket.OPEN || 
           this.metricsWs?.readyState === WebSocket.OPEN;
  }
}

// Singleton instance
export const nidsWebSocket = new NIDSWebSocket();
export default nidsWebSocket;
