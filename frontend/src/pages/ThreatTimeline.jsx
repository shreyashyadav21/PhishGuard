import React, { useState, useEffect } from 'react';
import {
  Clock,
  Search,
  Filter,
  ShieldAlert,
  AlertTriangle,
  FolderMinus,
  Trash2,
  CheckCircle2,
  AlertOctagon,
  Radio,
  RefreshCw
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';

export default function ThreatTimeline() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState('all');
  const [eventType, setEventType] = useState('all');
  const [search, setSearch] = useState('');

  const fetchTimeline = async () => {
    setLoading(true);
    try {
      let query = `/timeline?`;
      if (severity !== 'all') query += `severity=${encodeURIComponent(severity)}&`;
      if (eventType !== 'all') query += `event_type=${encodeURIComponent(eventType)}&`;
      if (search.trim()) query += `search=${encodeURIComponent(search.trim())}&`;

      const res = await api.get(query);
      setEvents(res.data || []);
    } catch (err) {
      toast.error('Failed to load threat timeline events');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, [severity, eventType]);

  const handleSearch = (e) => {
    e.preventDefault();
    fetchTimeline();
  };

  const getEventIcon = (type, sev) => {
    if (type === 'quarantine') return <FolderMinus className="w-4 h-4 text-amber-400" />;
    if (type === 'trash') return <Trash2 className="w-4 h-4 text-rose-400" />;
    if (type === 'keep') return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
    if (sev === 'critical') return <AlertOctagon className="w-4 h-4 text-rose-400" />;
    if (sev === 'high') return <AlertTriangle className="w-4 h-4 text-orange-400" />;
    return <Clock className="w-4 h-4 text-cyan-400" />;
  };

  return (
    <div className="space-y-6 pb-12 max-w-4xl mx-auto">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 space-y-2">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 text-[#00D4FF] flex items-center justify-center border border-cyan-500/20 shadow-md">
            <Clock className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Personal Threat Timeline</h2>
            <p className="text-xs text-[#9BAAC0]">
              Chronological security audit trail of incoming detections, user actions, quarantine isolations, and policy events.
            </p>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-card p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        <form onSubmit={handleSearch} className="relative w-full md:w-72">
          <input
            type="text"
            placeholder="Search timeline events..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#080E19] border border-white/10 rounded-xl px-4 py-2 pl-9 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#00D4FF]"
          />
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
        </form>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Event Type Filter */}
          <select
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            className="bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#00D4FF]"
          >
            <option value="all">All Events</option>
            <option value="threat_identified">Threats Flagged</option>
            <option value="email_detected">Emails Ingested</option>
            <option value="quarantine">Quarantine Actions</option>
            <option value="trash">Trash Actions</option>
            <option value="keep">Keep Actions</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#00D4FF]"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="info">Info / Clean</option>
          </select>
        </div>
      </div>

      {/* Vertical Timeline View */}
      <div className="relative border-l-2 border-white/10 ml-6 space-y-6">
        {events.length > 0 ? (
          events.map((ev) => (
            <div key={ev.id} className="relative pl-6">
              {/* Timeline Marker Dot */}
              <div className="absolute -left-[17px] top-1.5 w-8 h-8 rounded-full bg-[#101A2B] border-2 border-cyan-400 flex items-center justify-center">
                {getEventIcon(ev.event_type, ev.severity)}
              </div>

              <div className="soc-card p-4 space-y-2 hover:border-cyan-500/40 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <h3 className="text-xs font-bold text-white">{ev.title}</h3>
                    <span
                      className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
                        ev.severity === 'critical'
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          : ev.severity === 'high'
                          ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                          : ev.severity === 'medium'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20'
                      }`}
                    >
                      {ev.severity}
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-400 font-mono">
                    {ev.created_at ? new Date(ev.created_at).toLocaleString() : ''}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{ev.description}</p>

                {ev.target_item && (
                  <div className="text-[10px] font-mono text-cyan-400/90 bg-[#080E19] px-2.5 py-1 rounded inline-block truncate max-w-full">
                    Target: {ev.target_item}
                  </div>
                )}
              </div>
            </div>
          ))
        ) : (
          <div className="soc-card p-8 text-center text-xs text-slate-400">
            No security events found matching the selected filters.
          </div>
        )}
      </div>
    </div>
  );
}

