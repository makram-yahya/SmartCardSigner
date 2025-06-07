let latestSignature = "";

async function signPdf() {
  const fileInput = document.getElementById('pdfFile');
  const status = document.getElementById('status');
  const downloadLink = document.getElementById('downloadLink');
  const copyBtn = document.getElementById('copyBtn');
  const signatureBox = document.getElementById('signatureBox');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');

  // Reset UI
  progressContainer.style.display = "block";
  progressBar.style.width = "0%";
  status.innerText = "";
  downloadLink.style.display = "none";
  copyBtn.style.display = "none";
  signatureBox.style.display = "none";
  signatureBox.value = "";

  if (!fileInput.files.length) {
    alert("Please choose a PDF file.");
    return;
  }

  const file = fileInput.files[0];
  status.innerText = "Reading file...";
  progressBar.style.width = "20%";

  const arrayBuffer = await file.arrayBuffer();
  const base64Content = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));

  progressBar.style.width = "40%";
  status.innerText = "Preparing request...";

  const requestPayload = {
    dataToSign: [
      {
        id: "doc1",
        contentB64: base64Content,
        params: {
          signPdfAsP7m: true,
          visibleSignature: false
        }
      }
    ],
    dllList: ["C:\\\\Windows\\\\System32\\\\akisp11.dll"]
  };

  const socket = new WebSocket("ws://localhost:8765/websockets/sign");

  socket.onopen = () => {
    status.innerText = "Sending to signer...";
    progressBar.style.width = "60%";
    socket.send(JSON.stringify(requestPayload));
  };

  socket.onmessage = (event) => {
    progressBar.style.width = "90%";
    const response = JSON.parse(event.data);
    latestSignature = response.dataSigned[0].contentB64;

    const blob = new Blob([Uint8Array.from(atob(latestSignature), c => c.charCodeAt(0))], { type: "application/pkcs7-signature" });
    const url = URL.createObjectURL(blob);
    downloadLink.href = url;
    downloadLink.download = "signed.p7m";
    downloadLink.style.display = "inline-block";

    signatureBox.value = latestSignature;
    signatureBox.style.display = "block";
    copyBtn.style.display = "inline-block";

    progressBar.style.width = "100%";
    status.innerText = "Signature successful!";
    socket.close();
  };

  socket.onerror = (err) => {
    status.innerText = "WebSocket error: " + err.message;
    progressBar.style.width = "0%";
  };
}

function copySignature() {
  const signatureBox = document.getElementById('signatureBox');
  signatureBox.select();
  document.execCommand("copy");
  alert("Signature copied to clipboard!");
}
