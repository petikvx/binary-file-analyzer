import React, { useState, useEffect } from 'react';
import { Hash, Clock, HardDrive, FileText, Download, Loader2, X, Code, Shield, Package, Zap } from 'lucide-react';

interface ImportedDLL {
  name: string;
  functions: string[];
}

interface FileInfo {
  name: string;
  size: number;
  type: string;
  lastModified: number;
  sha256: string;
  fileFormat: string;
  isDotNet: boolean;
  architecture: string;
  importedDLLs: ImportedDLL[];
  totalImportedFunctions: number;
  peInfo?: {
    isDLL: boolean;
    isExecutable: boolean;
    subsystem: string;
    compilationTimestamp?: string;
  };
}

interface FileAnalyzerProps {
  file: File;
  onRemove: () => void;
}

export const FileAnalyzer: React.FC<FileAnalyzerProps> = ({ file, onRemove }) => {
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(true);

  useEffect(() => {
    analyzeFile(file);
  }, [file]);

  const analyzeFile = async (file: File) => {
    setIsAnalyzing(true);
    
    try {
      // Read file as ArrayBuffer
      const arrayBuffer = await file.arrayBuffer();
      const uint8Array = new Uint8Array(arrayBuffer);
      
      // Calculate SHA-256 hash only
      const sha256 = await calculateHash(uint8Array, 'SHA-256');
      
      // Analyze file format and structure
      const fileAnalysis = analyzeFileStructure(uint8Array);
      
      setFileInfo({
        name: file.name,
        size: file.size,
        type: file.type || 'application/octet-stream',
        lastModified: file.lastModified,
        sha256,
        ...fileAnalysis
      });
    } catch (error) {
      console.error('Error analyzing file:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const calculateHash = async (data: Uint8Array, algorithm: string): Promise<string> => {
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const analyzeFileStructure = (data: Uint8Array) => {
    // Check for PE header (Windows executables)
    if (data.length >= 64 && data[0] === 0x4D && data[1] === 0x5A) { // MZ signature
      const peOffset = data[60] | (data[61] << 8) | (data[62] << 16) | (data[63] << 24);
      
      if (peOffset < data.length - 4 && 
          data[peOffset] === 0x50 && data[peOffset + 1] === 0x45 && 
          data[peOffset + 2] === 0x00 && data[peOffset + 3] === 0x00) { // PE signature
        
        return analyzePEFile(data, peOffset);
      }
    }
    
    // Check for ELF header (Linux executables)
    if (data.length >= 16 && 
        data[0] === 0x7F && data[1] === 0x45 && data[2] === 0x4C && data[3] === 0x46) { // ELF signature
      return analyzeELFFile(data);
    }
    
    // Check for Mach-O header (macOS executables)
    if (data.length >= 4) {
      const magic = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
      if (magic === 0xFEEDFACE || magic === 0xFEEDFACF || magic === 0xCAFEBABE) {
        return analyzeMachOFile(data);
      }
    }
    
    // Default analysis for unknown formats
    return {
      fileFormat: 'Unknown Binary',
      isDotNet: false,
      architecture: 'Unknown',
      importedDLLs: [],
      totalImportedFunctions: 0,
      peInfo: undefined
    };
  };

  const analyzePEFile = (data: Uint8Array, peOffset: number) => {
    const machineType = data[peOffset + 4] | (data[peOffset + 5] << 8);
    const characteristics = data[peOffset + 22] | (data[peOffset + 23] << 8);
    const subsystem = data[peOffset + 68] | (data[peOffset + 69] << 8);
    
    // Check for .NET by looking for CLR Runtime Header
    const isDotNet = checkForDotNetSignature(data, peOffset);
    
    const architecture = getArchitectureFromMachine(machineType);
    const isDLL = (characteristics & 0x2000) !== 0;
    const isExecutable = (characteristics & 0x0002) !== 0;
    
    const subsystemName = getSubsystemName(subsystem);
    
    // Try to get compilation timestamp
    const timestampOffset = peOffset + 8;
    const timestamp = data[timestampOffset] | (data[timestampOffset + 1] << 8) | 
                     (data[timestampOffset + 2] << 16) | (data[timestampOffset + 3] << 24);
    const compilationDate = timestamp > 0 ? new Date(timestamp * 1000).toLocaleString() : undefined;
    
    // Parse import table for DLLs and APIs
    const importInfo = parseImportTable(data, peOffset);
    
    return {
      fileFormat: isDotNet ? '.NET Assembly' : 'Windows PE',
      isDotNet,
      architecture,
      importedDLLs: importInfo.dlls,
      totalImportedFunctions: importInfo.totalFunctions,
      peInfo: {
        isDLL,
        isExecutable,
        subsystem: subsystemName,
        compilationTimestamp: compilationDate
      }
    };
  };

  const parseImportTable = (data: Uint8Array, peOffset: number) => {
    const importedDLLs: ImportedDLL[] = [];
    let totalFunctions = 0;

    try {
      // Get optional header size and magic
      const sizeOfOptionalHeader = data[peOffset + 20] | (data[peOffset + 21] << 8);
      if (sizeOfOptionalHeader < 96) return { dlls: importedDLLs, totalFunctions };

      const magic = data[peOffset + 24] | (data[peOffset + 25] << 8);
      const is64Bit = magic === 0x20b;
      
      // Calculate data directories offset
      const dataDirectoriesOffset = peOffset + 24 + (is64Bit ? 112 : 96);
      
      // Check if we have enough space for import table entry
      if (dataDirectoriesOffset + 16 > data.length) return { dlls: importedDLLs, totalFunctions };

      // Import table is at index 1 (0-based) in data directories
      const importTableRva = data[dataDirectoriesOffset + 8] | (data[dataDirectoriesOffset + 9] << 8) | 
                            (data[dataDirectoriesOffset + 10] << 16) | (data[dataDirectoriesOffset + 11] << 24);
      const importTableSize = data[dataDirectoriesOffset + 12] | (data[dataDirectoriesOffset + 13] << 8) | 
                             (data[dataDirectoriesOffset + 14] << 16) | (data[dataDirectoriesOffset + 15] << 24);

      if (importTableRva === 0 || importTableSize === 0) return { dlls: importedDLLs, totalFunctions };

      // Build section table for RVA to file offset conversion
      const sections = buildSectionTable(data, peOffset);
      
      // Convert RVA to file offset
      const importTableFileOffset = rvaToFileOffset(importTableRva, sections);
      if (importTableFileOffset === -1) return { dlls: importedDLLs, totalFunctions };

      // Parse import descriptors (each is 20 bytes)
      let currentOffset = importTableFileOffset;
      let descriptorCount = 0;
      
      while (currentOffset + 20 <= data.length && descriptorCount < 100) { // Limit to prevent infinite loops
        // Read import descriptor
        const originalFirstThunk = data[currentOffset] | (data[currentOffset + 1] << 8) | 
                                  (data[currentOffset + 2] << 16) | (data[currentOffset + 3] << 24);
        const nameRva = data[currentOffset + 12] | (data[currentOffset + 13] << 8) | 
                       (data[currentOffset + 14] << 16) | (data[currentOffset + 15] << 24);
        const firstThunk = data[currentOffset + 16] | (data[currentOffset + 17] << 8) | 
                          (data[currentOffset + 18] << 16) | (data[currentOffset + 19] << 24);

        // End of import table (all zeros)
        if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;

        if (nameRva !== 0) {
          const nameFileOffset = rvaToFileOffset(nameRva, sections);
          if (nameFileOffset !== -1 && nameFileOffset < data.length) {
            const dllName = readNullTerminatedString(data, nameFileOffset);
            if (dllName && dllName.length > 0) {
              const thunkRva = originalFirstThunk || firstThunk;
              const functions = parseImportFunctions(data, sections, thunkRva, is64Bit);
              
              if (functions.length > 0) {
                // Sort functions alphabetically
                const sortedFunctions = functions.sort((a, b) => a.localeCompare(b));
                
                importedDLLs.push({
                  name: dllName,
                  functions: sortedFunctions
                });
                totalFunctions += functions.length;
              }
            }
          }
        }

        currentOffset += 20;
        descriptorCount++;
      }
    } catch (error) {
      console.error('Error parsing import table:', error);
    }

    // Sort DLLs alphabetically by name
    importedDLLs.sort((a, b) => a.name.localeCompare(b.name));

    return { dlls: importedDLLs, totalFunctions };
  };

  const buildSectionTable = (data: Uint8Array, peOffset: number) => {
    const sections: Array<{virtualAddress: number, virtualSize: number, pointerToRawData: number, sizeOfRawData: number}> = [];
    
    try {
      const numberOfSections = data[peOffset + 6] | (data[peOffset + 7] << 8);
      const sizeOfOptionalHeader = data[peOffset + 20] | (data[peOffset + 21] << 8);
      
      // Section headers start after PE header + optional header
      const sectionHeadersOffset = peOffset + 24 + sizeOfOptionalHeader;
      
      // Each section header is 40 bytes
      for (let i = 0; i < numberOfSections && i < 50; i++) { // Limit sections
        const sectionOffset = sectionHeadersOffset + (i * 40);
        if (sectionOffset + 40 > data.length) break;
        
        const virtualSize = data[sectionOffset + 8] | (data[sectionOffset + 9] << 8) | 
                           (data[sectionOffset + 10] << 16) | (data[sectionOffset + 11] << 24);
        const virtualAddress = data[sectionOffset + 12] | (data[sectionOffset + 13] << 8) | 
                              (data[sectionOffset + 14] << 16) | (data[sectionOffset + 15] << 24);
        const sizeOfRawData = data[sectionOffset + 16] | (data[sectionOffset + 17] << 8) | 
                             (data[sectionOffset + 18] << 16) | (data[sectionOffset + 19] << 24);
        const pointerToRawData = data[sectionOffset + 20] | (data[sectionOffset + 21] << 8) | 
                                (data[sectionOffset + 22] << 16) | (data[sectionOffset + 23] << 24);
        
        sections.push({
          virtualAddress,
          virtualSize,
          pointerToRawData,
          sizeOfRawData
        });
      }
    } catch (error) {
      console.error('Error building section table:', error);
    }
    
    return sections;
  };

  const rvaToFileOffset = (rva: number, sections: Array<{virtualAddress: number, virtualSize: number, pointerToRawData: number, sizeOfRawData: number}>): number => {
    for (const section of sections) {
      if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
        const offset = section.pointerToRawData + (rva - section.virtualAddress);
        return offset;
      }
    }
    return -1;
  };

  const parseImportFunctions = (data: Uint8Array, sections: Array<{virtualAddress: number, virtualSize: number, pointerToRawData: number, sizeOfRawData: number}>, thunkRva: number, is64Bit: boolean): string[] => {
    const functions: string[] = [];
    
    try {
      const thunkFileOffset = rvaToFileOffset(thunkRva, sections);
      if (thunkFileOffset === -1) return functions;

      let currentOffset = thunkFileOffset;
      const thunkSize = is64Bit ? 8 : 4;
      let functionCount = 0;

      while (currentOffset + thunkSize <= data.length && functionCount < 500) { // Limit functions
        let thunkValue = 0;
        
        if (is64Bit) {
          // Read 64-bit value (little endian) - but only use lower 32 bits for simplicity
          thunkValue = data[currentOffset] | (data[currentOffset + 1] << 8) | 
                      (data[currentOffset + 2] << 16) | (data[currentOffset + 3] << 24);
          // Check if upper 32 bits indicate ordinal
          const upperBits = data[currentOffset + 4] | (data[currentOffset + 5] << 8) | 
                           (data[currentOffset + 6] << 16) | (data[currentOffset + 7] << 24);
          if (upperBits & 0x80000000) {
            thunkValue |= 0x80000000; // Set ordinal flag
          }
        } else {
          thunkValue = data[currentOffset] | (data[currentOffset + 1] << 8) | 
                      (data[currentOffset + 2] << 16) | (data[currentOffset + 3] << 24);
        }

        if (thunkValue === 0) break;

        // Check if it's an ordinal import (high bit set)
        const isOrdinal = (thunkValue & 0x80000000) !== 0;
        
        if (isOrdinal) {
          const ordinal = thunkValue & 0xFFFF;
          functions.push(`Ordinal ${ordinal}`);
        } else {
          // It's a name import
          const nameRva = thunkValue & 0x7FFFFFFF;
          const nameFileOffset = rvaToFileOffset(nameRva, sections);
          
          if (nameFileOffset !== -1 && nameFileOffset + 2 < data.length) {
            // Skip hint (2 bytes) and read function name
            const functionName = readNullTerminatedString(data, nameFileOffset + 2);
            if (functionName && functionName.length > 0 && functionName.length < 100) {
              functions.push(functionName);
            }
          }
        }

        currentOffset += thunkSize;
        functionCount++;
      }
    } catch (error) {
      console.error('Error parsing import functions:', error);
    }

    return functions;
  };

  const readNullTerminatedString = (data: Uint8Array, offset: number): string => {
    if (offset >= data.length) return '';
    
    let end = offset;
    while (end < data.length && data[end] !== 0 && (end - offset) < 256) { // Limit string length
      end++;
    }
    
    if (end === offset) return '';
    
    try {
      // Try to decode as ASCII first, then UTF-8
      const bytes = data.slice(offset, end);
      let result = '';
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];
        if (byte >= 32 && byte <= 126) { // Printable ASCII
          result += String.fromCharCode(byte);
        } else if (byte > 126) {
          // Try UTF-8 decoding for the rest
          try {
            result += new TextDecoder('utf-8', { fatal: true }).decode(bytes.slice(i));
            break;
          } catch {
            result += '?';
          }
        } else {
          result += '?';
        }
      }
      return result;
    } catch {
      return '';
    }
  };

  const analyzeELFFile = (data: Uint8Array) => {
    const elfClass = data[4]; // 1 = 32-bit, 2 = 64-bit
    const elfData = data[5]; // 1 = little-endian, 2 = big-endian
    const elfType = data[16] | (data[17] << 8);
    
    const architecture = elfClass === 1 ? 'x86' : 'x64';
    const endianness = elfData === 1 ? 'Little Endian' : 'Big Endian';
    
    return {
      fileFormat: `ELF ${elfClass === 1 ? '32-bit' : '64-bit'}`,
      isDotNet: false,
      architecture: `${architecture} (${endianness})`,
      importedDLLs: [],
      totalImportedFunctions: 0,
      peInfo: undefined
    };
  };

  const analyzeMachOFile = (data: Uint8Array) => {
    const magic = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    
    let format = 'Mach-O';
    let architecture = 'Unknown';
    
    if (magic === 0xFEEDFACE) {
      format = 'Mach-O 32-bit';
      architecture = 'x86';
    } else if (magic === 0xFEEDFACF) {
      format = 'Mach-O 64-bit';
      architecture = 'x64';
    } else if (magic === 0xCAFEBABE) {
      format = 'Universal Binary';
      architecture = 'Multi-arch';
    }
    
    return {
      fileFormat: format,
      isDotNet: false,
      architecture,
      importedDLLs: [],
      totalImportedFunctions: 0,
      peInfo: undefined
    };
  };

  const checkForDotNetSignature = (data: Uint8Array, peOffset: number): boolean => {
    // Look for CLR Runtime Header in the data directories
    const numberOfRvaAndSizes = data[peOffset + 92] | (data[peOffset + 93] << 8) | 
                               (data[peOffset + 94] << 16) | (data[peOffset + 95] << 24);
    
    if (numberOfRvaAndSizes >= 15) {
      // CLR Runtime Header is at index 14 (0-based)
      const clrHeaderOffset = peOffset + 96 + (14 * 8);
      if (clrHeaderOffset + 4 < data.length) {
        const clrRva = data[clrHeaderOffset] | (data[clrHeaderOffset + 1] << 8) | 
                      (data[clrHeaderOffset + 2] << 16) | (data[clrHeaderOffset + 3] << 24);
        return clrRva !== 0;
      }
    }
    
    // Alternative check: look for common .NET strings
    const dataString = new TextDecoder('utf-8', { fatal: false }).decode(data.slice(0, Math.min(data.length, 10000)));
    return dataString.includes('mscoree.dll') || 
           dataString.includes('_CorExeMain') || 
           dataString.includes('_CorDllMain') ||
           dataString.includes('.NET Framework');
  };

  const getArchitectureFromMachine = (machineType: number): string => {
    switch (machineType) {
      case 0x014c: return 'x86 (32-bit)';
      case 0x8664: return 'x64 (64-bit)';
      case 0x01c0: return 'ARM';
      case 0xaa64: return 'ARM64';
      case 0x0200: return 'Itanium';
      default: return `Unknown (0x${machineType.toString(16)})`;
    }
  };

  const getSubsystemName = (subsystem: number): string => {
    switch (subsystem) {
      case 1: return 'Native';
      case 2: return 'Windows GUI';
      case 3: return 'Windows Console';
      case 5: return 'OS/2 Console';
      case 7: return 'POSIX Console';
      case 9: return 'Windows CE GUI';
      case 10: return 'EFI Application';
      case 11: return 'EFI Boot Service Driver';
      case 12: return 'EFI Runtime Driver';
      case 13: return 'EFI ROM';
      case 14: return 'Xbox';
      case 16: return 'Windows Boot Application';
      default: return `Unknown (${subsystem})`;
    }
  };

  const formatFileSize = (bytes: number): string => {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    
    return `${size.toFixed(unitIndex === 0 ? 0 : 2)} ${units[unitIndex]}`;
  };

  const formatDate = (timestamp: number): string => {
    return new Date(timestamp).toLocaleString();
  };

  const exportResults = () => {
    if (!fileInfo) return;
    
    const results = {
      fileName: fileInfo.name,
      fileSize: formatFileSize(fileInfo.size),
      fileType: fileInfo.type,
      fileFormat: fileInfo.fileFormat,
      isDotNetAssembly: fileInfo.isDotNet,
      architecture: fileInfo.architecture,
      lastModified: formatDate(fileInfo.lastModified),
      peInfo: fileInfo.peInfo,
      importedDLLs: fileInfo.importedDLLs,
      totalImportedFunctions: fileInfo.totalImportedFunctions,
      hashes: {
        sha256: fileInfo.sha256
      },
      analysisDate: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${fileInfo.name}_analysis.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (isAnalyzing) {
    return (
      <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-200">
        <div className="flex items-center justify-center space-x-3 py-8">
          <Loader2 className="w-8 h-8 text-blue-600 animate-spin" />
          <span className="text-lg font-medium text-gray-700">Analyzing {file.name}...</span>
        </div>
      </div>
    );
  }

  if (!fileInfo) {
    return (
      <div className="bg-white rounded-xl shadow-lg p-6 border border-red-200">
        <div className="text-center py-8">
          <span className="text-lg font-medium text-red-600">Failed to analyze {file.name}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
      {/* Header */}
      <div className={`text-white p-6 ${fileInfo.isDotNet ? 'bg-gradient-to-r from-purple-600 to-indigo-600' : 'bg-gradient-to-r from-blue-600 to-cyan-600'}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {fileInfo.isDotNet ? <Code className="w-6 h-6" /> : <FileText className="w-6 h-6" />}
            <div>
              <h3 className="text-lg font-semibold truncate">{fileInfo.name}</h3>
              <p className="text-sm opacity-90">{fileInfo.fileFormat}</p>
            </div>
          </div>
          <button
            onClick={onRemove}
            className="p-1 hover:bg-white/20 rounded-full transition-colors duration-200"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="p-6 space-y-6">
        {/* .NET Badge */}
        {fileInfo.isDotNet && (
          <div className="flex items-center space-x-2 p-3 bg-gradient-to-r from-purple-50 to-indigo-50 rounded-lg border border-purple-200">
            <Shield className="w-5 h-5 text-purple-600" />
            <span className="font-semibold text-purple-800">.NET Assembly Detected</span>
          </div>
        )}

        {/* Basic Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center space-x-3 p-4 bg-gray-50 rounded-lg">
            <HardDrive className="w-5 h-5 text-gray-600" />
            <div>
              <p className="text-sm text-gray-500">File Size</p>
              <p className="font-semibold text-gray-900">{formatFileSize(fileInfo.size)}</p>
            </div>
          </div>
          
          <div className="flex items-center space-x-3 p-4 bg-gray-50 rounded-lg">
            <Clock className="w-5 h-5 text-gray-600" />
            <div>
              <p className="text-sm text-gray-500">Last Modified</p>
              <p className="font-semibold text-gray-900">{formatDate(fileInfo.lastModified)}</p>
            </div>
          </div>
        </div>

        {/* File Format and Architecture */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-blue-50 rounded-lg">
            <p className="text-sm text-blue-600 mb-1">File Format</p>
            <p className="font-semibold text-blue-900">{fileInfo.fileFormat}</p>
          </div>
          
          <div className="p-4 bg-green-50 rounded-lg">
            <p className="text-sm text-green-600 mb-1">Architecture</p>
            <p className="font-semibold text-green-900">{fileInfo.architecture}</p>
          </div>
        </div>

        {/* PE Information */}
        {fileInfo.peInfo && (
          <div className="p-4 bg-orange-50 rounded-lg border border-orange-200">
            <h4 className="font-semibold text-orange-800 mb-3">PE File Information</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-orange-600">Type: </span>
                <span className="font-medium text-orange-900">
                  {fileInfo.peInfo.isDLL ? 'Dynamic Link Library (DLL)' : 
                   fileInfo.peInfo.isExecutable ? 'Executable' : 'Unknown'}
                </span>
              </div>
              <div>
                <span className="text-orange-600">Subsystem: </span>
                <span className="font-medium text-orange-900">{fileInfo.peInfo.subsystem}</span>
              </div>
              {fileInfo.peInfo.compilationTimestamp && (
                <div className="md:col-span-2">
                  <span className="text-orange-600">Compiled: </span>
                  <span className="font-medium text-orange-900">{fileInfo.peInfo.compilationTimestamp}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Imported DLLs and APIs */}
        {fileInfo.importedDLLs.length > 0 && (
          <div className="space-y-4">
            <div className="flex items-center space-x-2 mb-3">
              <Package className="w-5 h-5 text-gray-600" />
              <h4 className="text-lg font-semibold text-gray-900">
                Imported DLLs ({fileInfo.importedDLLs.length})
              </h4>
              <span className="text-sm text-gray-500">
                • {fileInfo.totalImportedFunctions} total functions
              </span>
            </div>
            
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {fileInfo.importedDLLs.map((dll, index) => (
                <div key={index} className="border border-gray-200 rounded-lg">
                  <div className="p-4 bg-gradient-to-r from-teal-50 to-cyan-50 border-b border-gray-200">
                    <div className="flex items-center space-x-2">
                      <Zap className="w-4 h-4 text-teal-600" />
                      <span className="font-semibold text-teal-800">{dll.name}</span>
                      <span className="text-sm text-teal-600">({dll.functions.length} functions)</span>
                    </div>
                  </div>
                  
                  {dll.functions.length > 0 && (
                    <div className="p-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                        {dll.functions.slice(0, 50).map((func, funcIndex) => (
                          <div key={funcIndex} className="text-sm font-mono text-gray-700 bg-gray-50 px-2 py-1 rounded">
                            {func}
                          </div>
                        ))}
                        {dll.functions.length > 50 && (
                          <div className="text-sm text-gray-500 italic">
                            ... and {dll.functions.length - 50} more functions
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Hashes */}
        <div className="space-y-4">
          <div className="flex items-center space-x-2 mb-3">
            <Hash className="w-5 h-5 text-gray-600" />
            <h4 className="text-lg font-semibold text-gray-900">Cryptographic Hash</h4>
          </div>
          
          <div className="p-4 bg-gradient-to-r from-purple-50 to-violet-50 rounded-lg border border-purple-200">
            <p className="text-sm font-medium text-purple-700 mb-2">SHA-256</p>
            <p className="font-mono text-sm text-purple-800 break-all">{fileInfo.sha256}</p>
          </div>
        </div>

        {/* Export Button */}
        <div className="pt-4 border-t border-gray-200">
          <button
            onClick={exportResults}
            className={`w-full flex items-center justify-center space-x-2 px-4 py-3 text-white rounded-lg transition-all duration-200 font-medium ${
              fileInfo.isDotNet 
                ? 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700'
                : 'bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700'
            }`}
          >
            <Download className="w-5 h-5" />
            <span>Export Analysis Results</span>
          </button>
        </div>
      </div>
    </div>
  );
};