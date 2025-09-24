import { useState, useRef, useEffect } from "react";
import Theme from "../components/Theme";
import Scan from "../components/Scan"
import ARV_extractor from "../components/ARV_extractor"
import History from "../components/History";
import axios from "axios";
import 'react-circular-progressbar/dist/styles.css';
import { CircularProgressbar } from 'react-circular-progressbar';

const API_KEY = "cd5325a1662758dae81656a6a25b8c1291248e94fa8057d143717d6173ff04d5";
import gsap from "gsap";
const DELAY_MS = 3000;
function Dashboard() {
  const [file, setFile] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false); // Nuevo estado para el menú móvil
  const [history, setHistory] = useState([]);
  const [msgError, setMsgError] = useState({
    msg:null,
    state:false,
  })
  const [selectNavbar, setSelectNavbar] = useState(0);
  const options = ['Escaner Archivo','Extractor de String','Historial']
  const sidebarRef = useRef(null)
  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    // Reinicia el resultado de análisis al cargar un nuevo archivo
    setAnalysisResult(null);
  };
 const scanFile = async () => {
    console.log('scanFile');
    if (!file) {
      console.error("No hay archivo para escanear.");
      return;
    }

    setIsScanning(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      // 1. Enviar el archivo para escanear
      const response = await fetch('https://www.virustotal.com/api/v3/files', {
        method: 'POST',
        headers: {
          'x-apikey': API_KEY,
        },
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Error al subir el archivo: ${response.status}`);
      }

      const data = await response.json();

      if (data.error) {
        console.error("Error al subir el archivo:", data.error.message);
        setIsScanning(false);
        return;
      }

      const analysisId = data.data.id;
      console.log("Archivo enviado. ID de análisis:", analysisId);

      // 2. Poll the API for the analysis results (with a delay)
      let analysisData = null;
      let count = 0;
      const MAX_RETRIES = 10;

      while (count < MAX_RETRIES) {
        const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          method: 'GET',
          headers: { 'x-apikey': API_KEY },
        });

        if (!analysisResponse.ok) {
          throw new Error(`Error al obtener el análisis: ${analysisResponse.status}`);
        }

        analysisData = await analysisResponse.json();

        if (analysisData.data.attributes.status === 'completed') {
          break;
        }

        await new Promise(resolve => setTimeout(resolve, DELAY_MS));
        count++;
      }

      // Update state with the final result
      if (analysisData && analysisData.data.attributes.status === 'completed') {
        console.log("Análisis completado:", analysisData.data.attributes.results);
        setAnalysisResult(analysisData.data.attributes.results);
      } else {
        console.warn("Análisis no completado a tiempo. Intente de nuevo más tarde.");
      }
      refreshMsgError();
      console.log('finally: ', msgError);

    } catch (error) {
      console.error("Hubo un error al escanear el archivo:", error);
      setMsgError({msg: '', state: false});
      setMsgError({msg: 'Hubo un error al escanear el archivo', state: true});

      console.log('catch: ', msgError);
    } finally {
      setIsScanning(false);
    }
};
  useEffect(() => {
  if (file) {
    scanFile();
  }
}, [file]);
function refreshMsgError(){
  setMsgError({msg:null , state:!msgError.state})
}
  
  function handleEmptyFile(){
    setFile(null)
  }
  // Calcula los contadores para el componente CircularProgressbar
  const maliciousCount = analysisResult ? Object.values(analysisResult).filter(r => r.category === 'malicious').length : 0;
  const totalAnalyzers = analysisResult ? Object.keys(analysisResult).length : 65;

useEffect(() => {
  // Asegúrate de que la referencia exista
  if (!sidebarRef.current) return;

  // Usa GSAP.set() para establecer el estado inicial sin animación si estamos en móvil
  if (window.innerWidth < 768) {
    gsap.set(sidebarRef.current, {
      left: '-100vw',
      opacity: 0,
    });
  }

  // Luego, maneja la animación de apertura y cierre
  if (isMobileMenuOpen && window.innerWidth < 768) {
    // Animación de entrada
    gsap.to(sidebarRef.current, {
      left: 0,
      opacity: 1,
      duration: 0.7,
      ease: "power2.out",
    });
  } else if (!isMobileMenuOpen && window.innerWidth < 768) {
    // Animación de salida
    gsap.to(sidebarRef.current, {
      left: '-100vw',
      opacity: 0,
      duration: 0.7,
      ease: "power2.in",
    });
  }
}, [isMobileMenuOpen]);
  /* ... (El código anterior de importaciones y estados permanece igual) ... */

  return (
    <div className="App w-screen h-screen md:max-h-screen bg-slate-100 dark:bg-slate-900 overflow-hidden">
      <div className="w-full h-full md:max-h-screen grid md:grid-cols-7">
        {/* --- Sidebar Desktop --- */}
        <div
          ref={sidebarRef}
          className="
            md:col-span-1
            bg-white dark:bg-slate-950 flex flex-col items-center justify-between p-6 shadow-xl border-r border-gray-200 dark:border-slate-800
             w-2/3 md:w-full fixed left-[-100vw] md:static transition-all duration-1000 ease-in-out h-screen z-20 md:z-0
          "
        >
          <header className="flex flex-col items-center justify-center gap-2 mb-8">
            <svg className="fill-red-600 dark:fill-red-500 size-16" xmlns="http://www.w3.org/2000/svg" xmlSpace="preserve" viewBox="0 0 512 512"><path d="m502.6 303.8-36.3-30.1a20.3 20.3 0 0 1 0-35.4l36.3-30.1a18.2 18.2 0 0 0-9.1-34.1l-46.6-8a20.2 20.2 0 0 1-17.6-30.5l16.4-44.3a18.2 18.2 0 0 0-25-25l-44.2 16.5A20.2 20.2 0 0 1 345.8 65L338 18.5a18.2 18.2 0 0 0-34.1-9.1l-30.1 36.3a20.3 20.3 0 0 1-35.4 0L208.2 9.4a18.2 18.2 0 0 0-34.1 9.1l-8 46.6a20.2 20.2 0 0 1-30.6 17.7L91.3 66.3a18.2 18.2 0 0 0-25 25l16.4 44.3a20.2 20.2 0 0 1-17.6 30.6L18.5 174a18.2 18.2 0 0 0-9.1 34l36.3 30.2a20.2 20.2 0 0 1 0 35.4L9.4 303.8a18.2 18.2 0 0 0 9.1 34.1l46.6 8a20.2 20.2 0 0 1 17.6 30.5l-16.4 44.3a18.2 18.2 0 0 0 25 25l44.2-16.4a20.2 20.2 0 0 1 30.7 17.6l7.9 46.6a18.2 18.2 0 0 0 34.1 9.1l30.1-36.3a20.3 20.3 0 0 1 35.4 0l30.1 36.3a18.2 18.2 0 0 0 34.1-9.1l8-46.6a20.2 20.2 0 0 1 30.6-17.6l44.2 16.4a18.2 18.2 0 0 0 25-25l-16.4-44.3a20.2 20.2 0 0 1 17.6-30.6l46.6-7.9a18.2 18.2 0 0 0 9.1-34.1zm-359.2-54.9c0-3 1.2-5.8 3.3-7.9l19.3-19.3-20.4-20.4a11.2 11.2 0 0 1 15.8-15.8l20.4 20.4 20.4-20.4a11 11 0 0 1 15.8 0 11.1 11.1 0 0 1 0 15.8l-20.4 20.4 19.3 19.3a11 11 0 0 1 0 15.8 11.1 11.1 0 0 1-15.8 0l-19.3-19.3-19.3 19.3a11.1 11.1 0 0 1-15.8 0 11 11 0 0 1-3.3-7.9zm211.1 92.3a26.7 26.7 0 0 1-19.8-8.5l-3.6-3.8c-1.8-2-3.4-3.8-4.8-4.7a7.7 7.7 0 0 0-4.7-1.4c-1.8 0-2.8.4-3.6.8-1 .5-2 1.2-3.2 2.4l-2.5 2.8c-2.2 2.4-4.8 5.4-8.6 8-3 2-8 4.4-14.7 4.4h-.2a26.6 26.6 0 0 1-19.8-8.5c-1.4-1.3-2.6-2.7-3.6-3.9-1.9-2-3.4-3.7-4.8-4.6a7.7 7.7 0 0 0-4.7-1.4c-1.7 0-2.7.3-3.6.8-1 .5-2 1.2-3.2 2.4l-2.5 2.8c-2.2 2.4-4.8 5.4-8.6 8-3 2-7.9 4.4-14.6 4.4a27 27 0 0 1-20-8.5c-1.5-1.4-2.7-2.7-3.8-4-1.8-2-3.3-3.7-4.7-4.5a7.6 7.6 0 0 0-4.7-1.4c-1.8 0-2.8.4-3.6.8-.9.5-1.9 1.2-3 2.4-1 .8-1.8 1.8-2.7 2.8-2.1 2.4-4.7 5.4-8.5 8-3 2-8 4.4-14.7 4.4a9.3 9.3 0 0 1-9.5-9.2c0-5.1 4.2-9.3 9.3-9.3 1.8 0 2.8-.3 3.6-.7 1-.5 2-1.3 3.1-2.4l2.7-2.8c2-2.4 4.7-5.4 8.4-8a26.9 26.9 0 0 1 34.7 4l3.7 4c1.8 2 3.4 3.7 4.8 4.6 1.3.9 2.4 1.3 4.6 1.3 1.9 0 2.8-.3 3.7-.7.9-.5 1.9-1.2 3-2.4l2.7-2.8c2-2.4 4.7-5.4 8.5-8a27 27 0 0 1 34.7 4l3.7 4c1.8 2 3.4 3.7 4.7 4.6 1.4.9 2.5 1.3 4.7 1.3 1.7 0 2.7-.3 3.7-.7.9-.5 1.9-1.2 3-2.4l2.7-2.8c2.1-2.4 4.7-5.4 8.5-8a27 27 0 0 1 34.7 4l3.7 4c1.8 2 3.4 3.7 4.8 4.6 1.3.9 2.4 1.3 4.7 1.3a9.2 9.2 0 0 1 0 18.5zM365.3 241a11.2 11.2 0 0 1-7.9 19c-3 0-5.8-1-7.9-3.2l-19.3-19.3-19.3 19.3a11.1 11.1 0 0 1-15.8 0 11 11 0 0 1 0-15.8l19.3-19.3-20.4-20.4a11.1 11.1 0 0 1 0-15.8 11.1 11.1 0 0 1 15.8 0l20.4 20.4 20.4-20.4a11.1 11.1 0 0 1 15.8 0 11.2 11.2 0 0 1 0 15.8L346 221.7l19.3 19.3z" /></svg>
            <span className="text-2xl font-bold dark:text-gray-200">MalwareScan</span>
          </header>
          <ul className="flex flex-col items-start justify-center gap-4">
            {options.map((option, index) =>
              <li onClick={()=>setSelectNavbar(index)} key={index} className={`font-bold cursor-pointer hover:underline transition-all duration-300 ease-in-out ${selectNavbar==index? 'text-slate-600': 'text-slate-950 dark:text-slate-50 '}`}>
                {option}
              </li>
            )}
          </ul>
          <div className="bg-blue-50 dark:bg-blue-950 p-4 rounded-xl border border-blue-200 dark:border-blue-900 shadow-sm flex flex-col gap-2">
            <h3 className="text-sm font-semibold text-blue-800 dark:text-blue-200">
              Detector de virus
            </h3>
            <p className="text-xs text-blue-600 dark:text-blue-400">
              Analiza archivos de todo tipo: PDF, Word, Excel, ZIP, RAR, y muchos más. ¡Sube tu documento y protégete!
            </p>
          </div>
          <div>
            <div className="flex flex-col h-full items-center justify-center gap-2">
              <span className="text-center text-gray-500 dark:text-gray-400 text-sm mt-auto">
                Hi, José Herrera 👋
              </span>
              {/* Botón de cerrar sesión */}
              <button className="w-full py-3 px-4 rounded-lg bg-gray-100 dark:bg-slate-800 hover:bg-red-100 dark:hover:bg-red-800 transition-colors duration-200 text-gray-700 dark:text-gray-300 font-medium flex items-center justify-center gap-3 cursor-pointer">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
                Cerrar Sesión
              </button>
            </div>
          </div>
        </div>

        {/* Overlay oscuro para el móvil */}
        {isMobileMenuOpen && (
          <div
            className="fixed inset-0 bg-slate-100/60 dark:bg-slate-950/60 z-10 md:hidden transition-all duration-1000 ease-linear"
            onClick={() => setIsMobileMenuOpen(false)}
          >
          </div>
        )}
        {/* --- Contenido Principal Condicional --- */}
        <div id="content" className="w-screen h-screen md:w-full md:h-full md:col-span-6 flex flex-col gap-6 p-6 overflow-hidden transition-all duration-300 ease-in-out">

          {/* --- Barra superior --- */}
          <div className="bg-white dark:bg-slate-950 rounded-xl shadow-sm p-4 flex items-center justify-between border border-gray-200 dark:border-slate-800">
            <div className="flex items-center gap-4">
              <svg onClick={() => setIsMobileMenuOpen(true)} className="size-8 text-slate-900 dark:text-slate-100 md:hidden" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><path stroke="#464455" strokeLinecap="round" strokeLinejoin="round" d="M5 8h8.8M5 12h14m-8.8 4H19" /></svg>
              <h1 className="text-xl font-semibold text-gray-800 dark:text-gray-200">Dashboard de Análisis</h1>
            </div>
            <Theme />
          </div>
           {/* --- Nuevo diseño para el archivo cargado --- */}
          {file && selectNavbar!=2 && (
            <div className="bg-white dark:bg-slate-950 p-6 rounded-xl shadow-sm flex flex-col border border-gray-200 dark:border-slate-800">
              {/* Contenedor principal para la información del archivo y el círculo */}
              <div className="flex justify-between items-start mb-6 w-full">
                {/* Contenedor del círculo */}
                <div className="flex-shrink-0 mr-6 mt-2">
                  <ScanProgressCircle maliciousCount={maliciousCount} totalAnalyzers={totalAnalyzers} />
                </div>

                {/* Contenedor de la información del archivo */}
                <div className="flex-grow flex flex-col">
                  <div className="w-full flex justify-between items-center mb-4">
                    <h2 className={`text-xl font-bold flex items-center gap-2 ${maliciousCount > 0 ? 'text-red-600 dark:text-red-500' : 'text-green-600 dark:text-green-500'}`}>
                      {maliciousCount > 0 ? (
                        <>
                          <svg className="h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856a2 2 0 001.789-2.895L12 3.895 3.333 18.105A2 2 0 005.125 21z" />
                          </svg>
                          Malicioso
                        </>
                      ) : (
                        <>
                          <svg className="h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                          Seguro
                        </>
                      )}
                    </h2>
                    <div className="flex items-center gap-2 cursor-pointer" onClick={handleEmptyFile}>
                      <button className="text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors cursor-pointer">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                          <path d="M12.9 14.32a8 8 0 11-1.414-1.414L18.586 19.586a2 2 0 01-2.828 2.828l-5.656-5.656z" />
                        </svg>
                      </button>
                      <button className="text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors cursor-pointer">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
                        </svg>
                      </button>
                      <button className="text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors cursor-pointer">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M3 3a1 1 0 011-1h12a1 1 0 011 1v1h-14V3zm0 3v13a2 2 0 002 2h10a2 2 0 002-2V6H3zm4-1a1 1 0 100 2h6a1 1 0 100-2H7z" clipRule="evenodd" />
                        </svg>
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col gap-1 mb-4">
                    <span className="text-xl font-bold text-gray-900 dark:text-gray-100">{file.name}</span>
                    <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                      <span>Tamaño: {(file.size / 1024).toFixed(2)} KB</span>
                      <span>•</span>
                      <span>Análisis reciente: Hace 8 minutos</span> {/* Puedes ajustar esto dinámicamente */}
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      <span className="bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300 text-xs font-medium px-2 py-0.5 rounded-full">
                        {file.type || 'Tipo desconocido'}
                      </span>
                      {/* Puedes agregar más etiquetas aquí */}
                    </div>
                  </div>

                  <div className="w-full flex items-center justify-between mt-auto">
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      <span className="font-semibold text-red-600 dark:text-red-500">{maliciousCount}</span> de <span className="font-semibold">{totalAnalyzers}</span> motores de análisis detectaron el archivo como malicioso.
                    </p>
                    <button
                      onClick={scanFile}
                      disabled={isScanning}
                      className={`py-2 px-4 rounded-lg font-semibold transition-colors duration-300 flex items-center gap-2 ${isScanning
                        ? 'bg-gray-400 cursor-not-allowed text-white'
                        : 'bg-blue-600 hover:bg-blue-700 cursor-pointer text-white'
                        }`}
                    >
                      {isScanning ? (
                        <>
                          <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          Escaneando...
                        </>
                      ) : (
                        'Reanalizar'
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Renderiza el área de carga solo si no hay un archivo */}
          {!file && selectNavbar!=2 && (
            <div className="bg-white dark:bg-slate-950 p-8 rounded-xl shadow-sm flex flex-col items-center justify-center text-center border border-gray-200 dark:border-slate-800">

              <h2 className="text-2xl font-bold text-gray-800 dark:text-gray-200 mb-4">Escanea tu archivo ahora</h2>
              <p className="text-gray-500 mb-6">Arrastra y suelta tu archivo aquí, o haz clic para subirlo.</p>

              <label htmlFor="file-upload" className="w-full h-40 md:h-64 flex flex-col items-center justify-center border-2 border-dashed border-gray-300 dark:border-slate-700 rounded-2xl p-6 transition-colors duration-200 hover:border-blue-500 cursor-pointer">
                <svg xmlns="http://www.w3.org/2000/svg" className="size-12 text-gray-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                <span className="mt-2 text-gray-600 dark:text-gray-400 font-medium">
                  Arrastra tu archivo aquí o <span className="text-blue-600 dark:text-blue-500">busca en tu dispositivo</span>
                </span>
                <input type="file" onChange={handleFileChange} id="file-upload" className="opacity-0 absolute size-64 cursor-pointer" />
              </label>
            </div>
          )}
          {selectNavbar==0 && <Scan file={file} maliciousCount={maliciousCount} totalAnalyzers={totalAnalyzers} analysisResult={analysisResult} isScanning={isScanning} scanFile={scanFile} handleEmptyFile={handleEmptyFile}></Scan>}
          {selectNavbar==1 && <ARV_extractor file={file}/>}
          {selectNavbar==2 && <History history={history}/>}
        </div>
      </div>
      {
        msgError.state && <Message msg={msgError.msg} state={msgError.state}/>
      }
    </div>
  );
}

function Message({msg,state}){
  const msgRef = useRef(null)
  useEffect(() => {
  // Create a new GSAP Timeline
  const tl = gsap.timeline({
    // Optional: add a delay to the entire timeline
    delay: 1
  });

  // Check if the ref exists before animating
  if (msgRef.current && state==true) {
    // Animation 1: From hidden to visible (y:100 to y:0)
    tl.fromTo(
      msgRef.current,
      { y: 100, opacity: 0.9 },
      { y: 0, opacity: 1, duration: 1 }
    )
    // Animation 2: Keep the message for a while
    .to(msgRef.current, {
      y: '-110vh',
      opacity: 0.5,
      duration: 4,
      delay: 3 // Wait 3 seconds before starting this animation
    })
    // Animation 3: Make it disappear completely
    .to(msgRef.current, {
      display: 'none',
      duration: 0.5
    });
  }

  // Optional: Cleanup function to kill the timeline when the component unmounts
  return () => tl.kill();

}, [state]);
  return(
    <div ref={msgRef} className="bg-slate-300/40 dark:bg-slate-800/40 dark:text-white shadow-2xl  fixed bottom-4 right-4 p-4 rounded-xl min-w-24 min-h-6 max-w-sm grid place-content-center border-b-2 border-b-red-500">
      <span className="text-sm text-justify">{msg}</span>
    </div>
  )
}
const ScanProgressCircle = ({ maliciousCount, totalAnalyzers }) => {
  const percentage = (maliciousCount / totalAnalyzers) * 100;
  const textColor = maliciousCount > 0 ? '#ef4444' : '#10b981'; // Rojo si es malicioso, verde si es seguro

  return (
    <div style={{ width: 140, height: 140 }} className="relative float-left">
      <CircularProgressbar
        value={percentage}
        text={`${maliciousCount}/${totalAnalyzers}`}
        styles={{
          path: {
            stroke: maliciousCount > 0 ? '#ef4444' : '#10b981',
            strokeLinecap: 'round',
            transition: 'stroke-dashoffset 0.5s ease 0s',
          },
          trail: {
            stroke: '#e5e7eb',
          },
          text: {
            fill: textColor,
            fontSize: '16px',
            fontWeight: 'bold',
          },
        }}
      />
      <div className="absolute inset-0 flex items-center justify-center flex-col">
        <div className="text-xs text-gray-500 mt-12">detectados</div>
      </div>
    </div>
  );
};
export default Dashboard;