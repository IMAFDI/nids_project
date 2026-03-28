import { useEffect, useState, useRef } from 'react';
import { Activity, AlertTriangle, AlertCircle, Info, Wifi, WifiOff } from 'lucide-react';
import { nidsWebSocket } from '../lib/websocket';
import clsx from 'clsx';

interface LiveEvent {
  id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  description: string;
  rule_name?: string;
  ml_score?: number;
}

const SEVERITY_CONFIG = {
  CRITICAL: { color: 'bg-red-600', icon: AlertCircle, textColor: 'text-red-600' },
  HIGH: { color: 'bg-orange-500', icon: AlertTriangle, textColor: 'text-orange-500' },
  MEDIUM: { color: 'bg-yellow-500', icon: Info, textColor: 'text-yellow-500' },
  LOW: { color: 'bg-blue-500', icon: Activity, textColor: 'text-blue-500' },
};

export default function LiveEventFeed({ maxEvents = 50 }: { maxEvents?: number }) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [eventQueue, setEventQueue] = useState<LiveEvent[]>([]);
  const feedRef = useRef<HTMLDivElement>(null);
  const eventIdCounter = useRef(0);

  // Process event queue with throttling (max 5 events per second)
  useEffect(() => {
    if (isPaused) return;

    const timer = setInterval(() => {
      setEventQueue((queue) => {
        if (queue.length === 0) return queue;

        // Take up to 5 events per second to keep the feed readable
        const batchSize = Math.min(5, queue.length);
        const batch = queue.slice(0, batchSize);

        setEvents((prev) => [...batch, ...prev].slice(0, maxEvents));
        return queue.slice(batchSize);
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [isPaused, maxEvents]);

  useEffect(() => {
    // Connect to WebSocket
    nidsWebSocket.connect();

    // Handle connection status
    const unsubConnection = nidsWebSocket.onConnectionChange((isConnected) => {
      setConnected(isConnected);
    });

    // Handle incoming events - add to queue instead of directly to events
    const unsubEvents = nidsWebSocket.onEvent((message) => {
      const eventData = message.data;
      const newEvent: LiveEvent = {
        id: `event-${++eventIdCounter.current}`,
        timestamp: eventData.timestamp || new Date().toISOString(),
        event_type: eventData.event_type || 'unknown',
        severity: eventData.severity || 'LOW',
        src_ip: eventData.src_ip || 'N/A',
        dst_ip: eventData.dst_ip || 'N/A',
        protocol: eventData.protocol || 'N/A',
        description: eventData.description || 'No description',
        rule_name: eventData.rule_name,
        ml_score: eventData.ml_score,
      };

      // Cap queue size to avoid unbounded growth during heavy bursts
      setEventQueue((prev) => [...prev, newEvent].slice(-500));

      // Play sound for critical events
      if (eventData.severity === 'CRITICAL') {
        playAlertSound();
      }
    });

    return () => {
      unsubConnection();
      unsubEvents();
    };
  }, []);

  const playAlertSound = () => {
    try {
      const audio = new Audio('data:audio/wav;base64,UklGRl9vT19XQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YU');
      audio.volume = 0.3;
      audio.play().catch(() => {});
    } catch (e) {
      // Ignore audio errors
    }
  };

  const formatTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString();
    } catch {
      return 'N/A';
    }
  };

  const clearEvents = () => {
    setEvents([]);
    setEventQueue([]);
  };

  return (
    <div className="bg-gray-900 rounded-lg shadow-lg overflow-hidden">
      {/* Header */}
      <div className="bg-gray-800 px-4 py-3 flex items-center justify-between border-b border-gray-700">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-green-400 animate-pulse" />
          <h3 className="text-lg font-semibold text-white">Live Event Feed</h3>
          <span className="text-sm text-gray-400">
            ({events.length} events)
          </span>
          {eventQueue.length > 0 && (
            <span className="text-xs text-yellow-400 bg-yellow-900/30 px-2 py-0.5 rounded">
              +{eventQueue.length} queued
            </span>
          )}
        </div>
        
        <div className="flex items-center gap-3">
          {/* Connection Status */}
          <div className={clsx(
            'flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
            connected ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'
          )}>
            {connected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
            {connected ? 'Connected' : 'Disconnected'}
          </div>
          
          {/* Pause/Resume */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={clsx(
              'px-3 py-1 rounded text-xs font-medium transition-colors',
              isPaused 
                ? 'bg-green-600 hover:bg-green-700 text-white'
                : 'bg-yellow-600 hover:bg-yellow-700 text-white'
            )}
          >
            {isPaused ? 'Resume' : 'Pause'}
          </button>
          
          {/* Clear */}
          <button
            onClick={clearEvents}
            className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Event List */}
      <div 
        ref={feedRef}
        className="h-96 overflow-y-auto"
        style={{ scrollBehavior: 'smooth' }}
      >
        {events.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            <div className="text-center">
              <Activity className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>Waiting for events...</p>
              <p className="text-sm">Events will appear here in real-time</p>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {events.map((event) => {
              const config = SEVERITY_CONFIG[event.severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.LOW;
              const Icon = config.icon;
              
              return (
                <div 
                  key={event.id}
                  className={clsx(
                    'px-4 py-3 hover:bg-gray-800 transition-colors',
                    event.severity === 'CRITICAL' && 'animate-pulse bg-red-900/20'
                  )}
                >
                  <div className="flex items-start gap-3">
                    {/* Severity Icon */}
                    <div className={clsx('p-1.5 rounded', config.color)}>
                      <Icon className="w-4 h-4 text-white" />
                    </div>
                    
                    {/* Event Details */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={clsx('text-xs font-bold', config.textColor)}>
                          {event.severity}
                        </span>
                        <span className="text-xs text-gray-500">
                          {formatTime(event.timestamp)}
                        </span>
                        <span className="text-xs px-1.5 py-0.5 bg-gray-700 rounded text-gray-300">
                          {event.event_type}
                        </span>
                      </div>
                      
                      <p className="text-sm text-white truncate">
                        {event.description}
                      </p>
                      
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-400">
                        <span>{event.src_ip} → {event.dst_ip}</span>
                        <span className="uppercase">{event.protocol}</span>
                        {event.rule_name && (
                          <span className="text-blue-400">Rule: {event.rule_name}</span>
                        )}
                        {event.ml_score && (
                          <span className="text-purple-400">ML: {(event.ml_score * 100).toFixed(0)}%</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
