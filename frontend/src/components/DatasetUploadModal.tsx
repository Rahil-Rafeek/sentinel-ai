import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  UploadCloud, 
  FileText, 
  CheckCircle2, 
  AlertTriangle, 
  X, 
  Sliders, 
  Activity, 
  ArrowRight,
  Database,
  Layers,
  Sparkles,
  RefreshCw
} from 'lucide-react';
import { api, DatasetUploadResponse } from '../services/api';

interface DatasetUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDatasetActivated: (datasetId: string) => void;
}

export const DatasetUploadModal: React.FC<DatasetUploadModalProps> = ({
  isOpen,
  onClose,
  onDatasetActivated,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadResult, setUploadResult] = useState<DatasetUploadResponse | null>(null);
  const [confirmedMapping, setConfirmedMapping] = useState<Record<string, string>>({});
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      handleFileSelected(droppedFile);
    }
  };

  const handleFileSelected = (selectedFile: File) => {
    if (!selectedFile.name.endsWith('.csv') && !selectedFile.name.endsWith('.txt')) {
      setUploadError('Only CSV (.csv) or text (.txt) tabular datasets are supported.');
      return;
    }
    setFile(selectedFile);
    setUploadError(null);
    performUpload(selectedFile);
  };

  const performUpload = async (uploadFile: File) => {
    setIsUploading(true);
    setUploadError(null);
    try {
      const result = await api.uploadDataset(uploadFile);
      setUploadResult(result);
      
      // Initialize mapping with suggested mapping
      const initialMap: Record<string, string> = {};
      Object.entries(result.suggested_mapping).forEach(([target, source]) => {
        if (source) initialMap[target] = source;
      });
      setConfirmedMapping(initialMap);
    } catch (err: any) {
      setUploadError(err.message || 'Dataset upload failed. Check CSV formatting.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleMappingChange = (targetField: string, sourceColumn: string) => {
    setConfirmedMapping(prev => ({
      ...prev,
      [targetField]: sourceColumn === 'NONE' ? '' : sourceColumn
    }));
  };

  const handleStartAnalysis = async () => {
    if (!uploadResult) return;
    setIsAnalyzing(true);
    setAnalysisProgress(10);

    try {
      // 1. Confirm column mapping
      await api.confirmMapping(uploadResult.dataset_id, confirmedMapping);
      setAnalysisProgress(30);

      // 2. Activate dataset
      await api.activateDataset(uploadResult.dataset_id);
      setAnalysisProgress(50);

      // 3. Start analysis job
      const jobRes = await api.startAnalysis(uploadResult.dataset_id, true);
      setAnalysisProgress(70);

      // 4. Poll job status
      const pollTimer = setInterval(async () => {
        try {
          const statusRes = await api.getJobStatus(jobRes.id);
          setAnalysisProgress(statusRes.progress_pct || 80);

          if (statusRes.status === 'completed') {
            clearInterval(pollTimer);
            setAnalysisProgress(100);
            setTimeout(() => {
              setIsAnalyzing(false);
              onDatasetActivated(uploadResult.dataset_id);
              onClose();
            }, 600);
          } else if (statusRes.status === 'failed') {
            clearInterval(pollTimer);
            setIsAnalyzing(false);
            setUploadError(statusRes.error_message || 'Analysis pipeline execution failed.');
          }
        } catch {
          // keep polling
        }
      }, 1000);
    } catch (err: any) {
      setIsAnalyzing(false);
      setUploadError(err.message || 'Failed to complete analysis pipeline.');
    }
  };

  const availableColumns = uploadResult ? Object.keys(uploadResult.data_profile.column_types) : [];

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={() => !isAnalyzing && onClose()}
          className="fixed inset-0 bg-obsidian-950/80 backdrop-blur-md"
        />

        {/* Modal Window */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          className="relative z-10 w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-3xl border border-slate-800 bg-obsidian-900/95 p-6 sm:p-8 shadow-2xl shadow-cyan-500/10 backdrop-blur-2xl"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-800 pb-5">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-500/40 text-cyan-400">
                <UploadCloud className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-xl font-black text-white">Ingest & Profile Cybersecurity Dataset</h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Upload CSV logs to auto-detect schema mappings, evaluate telemetry compatibility, and run the ML pipeline.
                </p>
              </div>
            </div>

            {!isAnalyzing && (
              <button
                onClick={onClose}
                className="rounded-lg border border-slate-800 p-2 text-slate-400 hover:text-white hover:border-slate-700"
              >
                <X className="h-5 w-5" />
              </button>
            )}
          </div>

          {/* Error Message */}
          {uploadError && (
            <div className="mt-4 flex items-center gap-2 rounded-xl bg-rose-950/60 border border-rose-500/50 p-3.5 text-xs font-bold text-rose-300">
              <AlertTriangle className="h-4 w-4 flex-shrink-0 text-rose-400" />
              <span>{uploadError}</span>
            </div>
          )}

          {/* Step 1: Upload Zone (if no file parsed yet) */}
          {!uploadResult && (
            <div className="mt-6">
              <div
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                className="group relative cursor-pointer rounded-2xl border-2 border-dashed border-slate-800 bg-obsidian-950/60 p-12 text-center transition-all hover:border-cyan-500/50 hover:bg-cyan-950/10"
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,.txt"
                  className="hidden"
                  onChange={(e) => e.target.files?.[0] && handleFileSelected(e.target.files[0])}
                />

                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-950/40 border border-cyan-500/30 text-cyan-400 group-hover:scale-110 transition-transform">
                  {isUploading ? (
                    <RefreshCw className="h-8 w-8 animate-spin" />
                  ) : (
                    <UploadCloud className="h-8 w-8" />
                  )}
                </div>

                <div className="mt-4 text-sm font-bold text-white">
                  {isUploading ? 'Parsing & Profiling Dataset...' : 'Drag and drop your cybersecurity CSV dataset here'}
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  Supports NetFlow, Zeek/Bro, Suricata, PCAP exports, and custom auth logs up to 50 MB
                </p>

                <div className="mt-4 inline-flex items-center gap-2 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-bold text-slate-300">
                  <span>Or click to browse local files</span>
                </div>
              </div>
            </div>
          )}

          {/* Step 2: Inferred Schema & Mapping Confirmation */}
          {uploadResult && (
            <div className="mt-6 space-y-6">
              {/* Compatibility & Quality Summary Banner */}
              <div className="rounded-2xl border border-slate-800 bg-obsidian-950 p-5">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-cyan-400" />
                    <span className="mono text-xs font-bold text-white">{uploadResult.filename}</span>
                    <span className="text-xs text-slate-400">
                      ({uploadResult.row_count.toLocaleString()} rows, {uploadResult.column_count} columns)
                    </span>
                  </div>

                  <span
                    className={`rounded-full px-3 py-0.5 text-xs font-black uppercase ${
                      uploadResult.compatibility_status === 'cybersecurity_compatible'
                        ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/50'
                        : uploadResult.compatibility_status === 'partially_compatible'
                        ? 'bg-amber-950/80 text-amber-300 border border-amber-500/50'
                        : 'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}
                  >
                    {uploadResult.compatibility_status.replace('_', ' ')}
                  </span>
                </div>

                {/* Compatibility Reasons */}
                <div className="mt-3 space-y-1">
                  {uploadResult.compatibility_reasons.map((reason, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-xs text-slate-300">
                      <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                      <span>{reason}</span>
                    </div>
                  ))}
                </div>

                {/* Quality Metrics */}
                <div className="mt-4 grid grid-cols-3 gap-3 border-t border-slate-800/80 pt-3 text-center text-xs">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase font-bold">Total Rows</span>
                    <div className="mono font-bold text-cyan-400 text-sm mt-0.5">
                      {uploadResult.row_count.toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase font-bold">Columns</span>
                    <div className="mono font-bold text-cyan-400 text-sm mt-0.5">
                      {uploadResult.column_count}
                    </div>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase font-bold">Duplicates</span>
                    <div className="mono font-bold text-slate-300 text-sm mt-0.5">
                      {uploadResult.data_profile.duplicate_rows}
                    </div>
                  </div>
                </div>
              </div>

              {/* Column Mapping Table */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    Semantic Field Mapping & Detector Alignment
                  </h3>
                  <span className="text-[11px] text-slate-400">
                    Adjust target mappings if your CSV headers differ
                  </span>
                </div>

                <div className="overflow-hidden rounded-xl border border-slate-800 bg-obsidian-950">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 bg-obsidian-900/80 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                      <tr>
                        <th className="py-2.5 px-4">Sentinel Target Field</th>
                        <th className="py-2.5 px-4">Your CSV Column</th>
                        <th className="py-2.5 px-4">Detection Role / Module</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {uploadResult.mapping_details.map((m) => {
                        const currentSource = confirmedMapping[m.target_field] || '';
                        return (
                          <tr key={m.target_field} className="hover:bg-obsidian-900/40">
                            <td className="py-2.5 px-4">
                              <span className="mono font-bold text-cyan-400">{m.target_field}</span>
                              <div className="text-[10px] text-slate-400">{m.explanation}</div>
                            </td>
                            <td className="py-2.5 px-4">
                              <select
                                value={currentSource || 'NONE'}
                                onChange={(e) => handleMappingChange(m.target_field, e.target.value)}
                                className="w-full rounded-lg border border-slate-700 bg-obsidian-900 px-2.5 py-1.5 text-xs text-white focus:border-cyan-400 focus:outline-none"
                              >
                                <option value="NONE">[ Unmapped / Not Present ]</option>
                                {availableColumns.map((col) => (
                                  <option key={col} value={col}>
                                    {col}
                                  </option>
                                ))}
                              </select>
                            </td>
                            <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                              {m.required_for.join(', ')}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Analysis Execution CTA */}
              <div className="border-t border-slate-800 pt-5 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => setUploadResult(null)}
                  disabled={isAnalyzing}
                  className="rounded-xl border border-slate-800 px-4 py-2.5 text-xs font-bold text-slate-400 hover:text-white hover:border-slate-700"
                >
                  Choose Different File
                </button>

                <div className="flex items-center gap-3">
                  {isAnalyzing && (
                    <div className="flex items-center gap-2">
                      <RefreshCw className="h-4 w-4 animate-spin text-cyan-400" />
                      <span className="mono text-xs font-bold text-cyan-400">
                        Analyzing Pipeline ({analysisProgress}%)
                      </span>
                    </div>
                  )}

                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={handleStartAnalysis}
                    disabled={isAnalyzing}
                    className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-3 text-xs font-black text-obsidian-950 shadow-lg shadow-cyan-500/25 hover:brightness-110 disabled:opacity-50"
                  >
                    <span>Confirm Mapping & Run Detection Pipeline</span>
                    <ArrowRight className="h-4 w-4" />
                  </motion.button>
                </div>
              </div>
            </div>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
