import { useEffect, useState } from 'react';
import { Activity, Cpu, HardDrive, Gauge, Zap, AlertTriangle } from 'lucide-react';
import { nidsWebSocket } from '../lib/websocket';
import clsx from 'clsx';

interface Metrics {
  packets_received: number;
  packets_processed: number;
  packets_dropped: number;
  queue_depth: number;
  avg_processing_time_ms: number;
  packets_per_second: number;
  events_per_minute: number;
  events_detected: number;
  uptime_seconds: number;
}

export default function LiveMetrics() {
  const [metrics, setMetrics] = useState<Metrics>({
    packets_received: 0,
    packets_processed: 0,
    packets_dropped: 0,
    queue_depth: 0,
    avg_processing_time_ms: 0,
    packets_per_second: 0,
    events_per_minute: 0,
    events_detected: 0,
    uptime_seconds: 0,
  });
  const [history, setHistory] = useState<{ pps: number; epm: number }[]>([]);

  useEffect(() => {
    nidsWebSocket.connect();

    const unsubMetrics = nidsWebSocket.onMetrics((message) => {
      const data = message.data;
      setMetrics({
        packets_received: data.packets_received || 0,
        packets_processed: data.packets_processed || 0,
        packets_dropped: data.packets_dropped || 0,
        queue_depth: data.queue_depth || 0,
        avg_processing_time_ms: data.avg_processing_time_ms || 0,
        packets_per_second: data.packets_per_second || 0,
        events_per_minute: data.events_per_minute || 0,
        events_detected: data.events_detected || 0,
        uptime_seconds: data.uptime_seconds || 0,
      });

      setHistory((prev) => {
        const updated = [...prev, { 
          pps: data.packets_per_second || 0, 
          epm: data.events_per_minute || 0 
        }];
        return updated.slice(-60); // Keep last 60 data points
      });
    });

    return () => {
      unsubMetrics();
    };
  }, []);

  const formatNumber = (num: number) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toFixed(0);
  };

  const formatUptime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${hours}h ${minutes}m ${secs}s`;
  };

  return (
    <div className="bg-gray-900 rounded-lg shadow-lg p-4">
      <div className="flex items-center gap-2 mb-4">
        <Gauge className="w-5 h-5 text-blue-400" />
        <h3 className="text-lg font-semibold text-white">Real-time Metrics</h3>
        <div className="flex-1" />
        <span className="text-xs text-gray-500">
          Uptime: {formatUptime(metrics.uptime_seconds)}
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Packets/sec */}
        <MetricCard
          icon={Zap}
          label="Packets/sec"
          value={metrics.packets_per_second.toFixed(1)}
          color="text-green-400"
          sparklineData={history.map(h => h.pps)}
        />

        {/* Events/min */}
        <MetricCard
          icon={AlertTriangle}
          label="Events/min"
          value={metrics.events_per_minute.toString()}
          color="text-yellow-400"
          sparklineData={history.map(h => h.epm)}
        />

        {/* Queue Depth */}
        <MetricCard
          icon={HardDrive}
          label="Queue Depth"
          value={formatNumber(metrics.queue_depth)}
          color="text-blue-400"
          warning={metrics.queue_depth > 5000}
        />

        {/* Avg Latency */}
        <MetricCard
          icon={Cpu}
          label="Avg Latency"
          value={`${metrics.avg_processing_time_ms.toFixed(2)}ms`}
          color="text-purple-400"
          warning={metrics.avg_processing_time_ms > 10}
        />
      </div>

      {/* Bottom Stats */}
      <div className="mt-4 pt-4 border-t border-gray-800 grid grid-cols-4 gap-4 text-center">
        <div>
          <div className="text-2xl font-bold text-white">{formatNumber(metrics.packets_received)}</div>
          <div className="text-xs text-gray-500">Total Packets</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-white">{formatNumber(metrics.packets_processed)}</div>
          <div className="text-xs text-gray-500">Processed</div>
        </div>
        <div>
          <div className={clsx(
            'text-2xl font-bold',
            metrics.packets_dropped > 0 ? 'text-red-400' : 'text-white'
          )}>
            {formatNumber(metrics.packets_dropped)}
          </div>
          <div className="text-xs text-gray-500">Dropped</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-yellow-400">{formatNumber(metrics.events_detected)}</div>
          <div className="text-xs text-gray-500">Events Detected</div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  color,
  sparklineData = [],
  warning = false,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  color: string;
  sparklineData?: number[];
  warning?: boolean;
}) {
  const sparklinePath = sparklineData.length > 1 
    ? getSparklinePath(sparklineData, 24, 60) 
    : '';

  return (
    <div className={clsx(
      'bg-gray-800 rounded-lg p-3',
      warning && 'ring-2 ring-yellow-500'
    )}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className={clsx('w-4 h-4', color)} />
        <span className="text-xs text-gray-400">{label}</span>
      </div>
      <div className="flex items-end justify-between">
        <span className={clsx('text-xl font-bold', color)}>{value}</span>
        {sparklineData.length > 1 && (
          <svg width="60" height="24" className="opacity-50">
            <path
              d={sparklinePath}
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              className={color}
            />
          </svg>
        )}
      </div>
    </div>
  );
}

function getSparklinePath(data: number[], height: number, width: number): string {
  if (data.length < 2) return '';
  const max = Math.max(...data, 1);
  const points = data.map((val, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - (val / max) * (height - 4) - 2;
    return `${x},${y}`;
  });
  return `M ${points.join(' L ')}`;
}
