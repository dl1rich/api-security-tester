interface WebSocketService {
  connect(sessionId?: string): void;
  disconnect(): void;
  send(message: any): void;
  subscribe(callback: (data: any) => void): () => void;
  isConnected(): boolean;
  getConnectionState(): string;
}

class WebSocketServiceImpl implements WebSocketService {
  private ws: WebSocket | null = null;
  private subscribers: ((data: any) => void)[] = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 3000;
  private sessionId?: string;
  private connectionState: 'disconnected' | 'connecting' | 'connected' | 'error' = 'disconnected';

  connect(sessionId?: string): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return; // Already connected
    }

    this.sessionId = sessionId;
    this.connectionState = 'connecting';
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = process.env.NODE_ENV === 'production' ? window.location.host : 'localhost:8000';
    const params = new URLSearchParams();
    
    if (sessionId) {
      params.append('session_id', sessionId);
    }
    params.append('subscriptions', 'all');
    
    const wsUrl = `${protocol}//${host}/api/v1/ws?${params.toString()}`;
    
    try {
      this.ws = new WebSocket(wsUrl);
      this.setupEventHandlers();
    } catch (error) {
      console.error('WebSocket connection failed:', error);
      this.connectionState = 'error';
      this.scheduleReconnect();
    }
  }

  private setupEventHandlers(): void {
    if (!this.ws) return;

    this.ws.onopen = () => {
      console.log('WebSocket connected');
      this.connectionState = 'connected';
      this.reconnectAttempts = 0;
      
      // Send initial ping
      this.send({
        type: 'ping',
        timestamp: new Date().toISOString()
      });
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.notifySubscribers(data);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };

    this.ws.onclose = (event) => {
      console.log('WebSocket disconnected:', event.code, event.reason);
      this.connectionState = 'disconnected';
      
      // Attempt to reconnect unless it was a deliberate close
      if (event.code !== 1000) { // 1000 = normal closure
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      this.connectionState = 'error';
    };
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      this.connectionState = 'error';
      return;
    }

    this.reconnectAttempts++;
    console.log(`Attempting to reconnect in ${this.reconnectInterval}ms (attempt ${this.reconnectAttempts})`);
    
    setTimeout(() => {
      this.connect(this.sessionId);
    }, this.reconnectInterval);
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close(1000, 'User disconnected');
      this.ws = null;
    }
    this.connectionState = 'disconnected';
    this.reconnectAttempts = 0;
  }

  send(message: any): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected, cannot send message:', message);
    }
  }

  subscribe(callback: (data: any) => void): () => void {
    this.subscribers.push(callback);
    
    // Return unsubscribe function
    return () => {
      const index = this.subscribers.indexOf(callback);
      if (index > -1) {
        this.subscribers.splice(index, 1);
      }
    };
  }

  private notifySubscribers(data: any): void {
    this.subscribers.forEach(callback => {
      try {
        callback(data);
      } catch (error) {
        console.error('Error in WebSocket subscriber:', error);
      }
    });
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  getConnectionState(): string {
    return this.connectionState;
  }

  // Convenience methods for specific notification types
  subscribeToTestProgress(callback: (progress: any) => void): () => void {
    return this.subscribe((data) => {
      if (data.type === 'test_progress') {
        callback(data.data);
      }
    });
  }

  subscribeToVulnerabilities(callback: (vulnerability: any) => void): () => void {
    return this.subscribe((data) => {
      if (data.type === 'vulnerability_found') {
        callback(data.data);
      }
    });
  }

  subscribeToTestStatus(callback: (status: any) => void): () => void {
    return this.subscribe((data) => {
      if (['test_started', 'test_completed', 'test_failed'].includes(data.type)) {
        callback({
          type: data.type,
          ...data.data
        });
      }
    });
  }

  subscribeToDetectorActivity(callback: (activity: any) => void): () => void {
    return this.subscribe((data) => {
      if (['detector_started', 'detector_completed'].includes(data.type)) {
        callback({
          type: data.type,
          ...data.data
        });
      }
    });
  }
}

// Export singleton instance
export const websocketService: WebSocketService = new WebSocketServiceImpl();