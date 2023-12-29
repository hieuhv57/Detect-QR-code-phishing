import QrScanner from "./scanner/qr-scanner.min.js";
QrScanner.WORKER_PATH = "./scanner/qr-scanner-worker.min.js";
var existingLinks = [];

const loadExistingLinks = async () => {
  try {
    // Get the path of the JSON file
    const jsonPath = chrome.runtime.getURL('src/data.json');

    // Use fetch to get the contents of a JSON file
    const response = await fetch(jsonPath);
    const data = await response.json();

    // Store data into the variable existingLinks
    existingLinks = data.links || [];
  } catch (error) {
    console.error('Error loading existing links:', error);
  }
};
loadExistingLinks();
const checkShortLink = (url) => {
  var domain = new URL(url).hostname;
  var containTLD = /(.ly|.gl|.shorte.st|qrco.de|.go2l.ink|x.co|ow.ly|t.co|tinyurl|tr.im|is.gd|cli.gs)(\/|)/;

  var matchedTLD = domain.match(containTLD);
  if (matchedTLD) {
    return true;
  }
  return false;
}

// Scans a given picture for a QR code.
function scan(currentTabPicture) {
  QrScanner.scanImage(currentTabPicture)
    .then((result) => updateLink(result))
    .catch(() => handleNoQRCode());
}

// Take picture of the current tab, and scan for a QR code.
chrome.tabs.captureVisibleTab(undefined, { format: "jpeg" }, scan);
// The function checks whether the link contains the character "-" or not
const containsHyphen = (link) => {
  var domain = new URL(link).hostname;
  return domain.includes("-");
};
// The function checks whether length of the domain name > 20
const lengthOfUrl = (url) => {
  var domain = new URL(url).hostname;
  return domain.length > 20;
};
// The function checks whether the link starts with "http" or not
const startsWithHttp = (link) => {
  return link.startsWith("http:");
};
// The function checks whether the link contains @ character
const symbolCheck = (url) => {
  return url.includes('@');
};
// The function checks whether the domain name contains more than 4 dots
const numberOfDot = (url) => {
  var domain = new URL(url).hostname;
  var countDots = (domain.match(/\./g) || []).length
  return countDots > 4;
};
// Update the link for the QR code.
async function updateLink(result) {
  var prefix = document.getElementById("prefix");
  var qrCodeOutput = document.getElementById("qr-code-link");
  var dangerNotification = document.getElementById("danger-notification");
  var alertMessageElement = document.getElementById("alert-message");
  var phishing_text = document.getElementById("phishing-text");
  var alertPhishing = document.getElementById("alert-Phishing");
  var alertShort = document.getElementById("alert-short");
  const linkExists = existingLinks.includes(result);
  // Display the result in the popup.html
  var main_text = document.getElementById("main-text");
  alertMessageElement.style.display = "none"; // Hide notifications before each update
  var y = -2.51778674;
  var totalScore = 0;

  if (checkShortLink(result) == true) {
    alertShort.innerText = "Có vẻ link bạn định truy cập là một URL rút gọn, chúng tôi không thể đánh giá phân tích dựa trên các yếu tố trong URL ";
    alertShort.style.display = "block";
    totalScore += 100;
  }
  if (linkExists) {
    phishing_text.innerHTML = "Phishing detected!<br>Mã QR này dẫn đến một trang Web lừa đảo, vui lòng không truy cập";
    totalScore += 100;
  } else {
    phishing_text.innerText = "";
  }
  const similarityResult = await checkSimilarDomain(result, 0.65);
  if (similarityResult === true) {
    if (!startsWithHttp(result)) {
      totalScore += 0;
    }
  }
  else if (similarityResult) {
    alertMessageElement.innerText = "Có vẻ link bạn định truy cập đang cố giả mạo trang web: " + similarityResult;
    alertMessageElement.style.display = "block";
    totalScore += 100;
  }

  const domainRegex = await fetchAndCheckURLWithRegex(result);
  if (domainRegex === true) {
    if (!startsWithHttp(result)) {
      totalScore += 0;
    }

  }
  else if (domainRegex) {
    alertMessageElement.innerText = "Có vẻ link bạn định truy cập đang cố giả mạo trang web: " + domainRegex;
    alertMessageElement.style.display = "block";
    totalScore += 100;
  }

  if (totalScore == 0) {
    if (numberOfDot(result)) {
      y += 0.42481838;
    }
    if (symbolCheck(result)) {
      y += 1.93626587;
    }
    if (lengthOfUrl(result)) {
      y += 5.19774284;
    }
    if (startsWithHttp(result)) {
      y += 7.44411332;
    }
    if (domainnameIsIP(result)) {
      y += 2.57152674;
    }
    if (CountDSlash(result)) {
      y += 2.88404282;
    }
    if (containsHyphen(result)) {
      y += 0.42481838;
    }
    var e = 2.718;
    totalScore = parseInt(String(100 * e ** y / (1 + e ** y)));
  }

  if (totalScore > 100) {
    totalScore = 100;
  }

  if (totalScore <= 7) {
    totalScore = 0;
  }

  if (totalScore >= 50) {
    dangerNotification.innerText = "NGUY HIỂM! Phát hiện dấu hiệu QR code Phishing";
    dangerNotification.style.display = "block";
  } else if (totalScore > 7) {
    dangerNotification.innerText = "Phát hiện dấu hiệu QR code Phishing";
    dangerNotification.style.display = "block";
  } else {
    dangerNotification.innerText = "Không phát hiện dấu hiệu nào ";
    dangerNotification.style.display = "block";
  }

  prefix.innerText = "Link:";

  qrCodeOutput.innerHTML = `<a id="qr-code-link" href="${result}" target="_blank">${result.length > 25 ? result.substring(0, 25) + "..." : result}</a>`;
  qrCodeOutput.setAttribute("href", result);
  qrCodeOutput.setAttribute("target", "_blank");

  document.getElementById('totalScore').innerText = totalScore;

  const totalScorePercentage = totalScore + "%";
  const totalScoreDisplay = document.getElementById("totalScore");
  totalScoreDisplay.innerText = totalScorePercentage;
  const totalScoreProgressBar = document.getElementById("totalScoreProgressBar");
  totalScoreProgressBar.value = totalScore;

  // Call function fetchData
  var virustotalScore = await fetchData(result);
  if (virustotalScore == true) {
    virustotalScore = 100;
    alertPhishing.innerText = "Nguy hiểm! VirusTotal nhận diện trang Web này là Phising";
    alertPhishing.style.display = "block";
  } else {
    virustotalScore = 0;
    alertPhishing.innerText = "VirusTotal nhận diện trang Web này là An toàn";
    alertPhishing.style.display = "block";
  }

  const virustotalScoreDisplay = document.getElementById("virustotalScore");
  virustotalScoreDisplay.innerText = virustotalScore + "%";
  const virustotaltotalScoreProgressBar = document.getElementById("virustotalScoreProgressBar");
  virustotaltotalScoreProgressBar.value = virustotalScore;
}

// Handler for when there is no QR code.
const handleNoQRCode = () => {
  var main_text = document.getElementById("main-text");
  main_text.innerText = "No QR Code Found";
};

// Check domain name is ip
const domainnameIsIP = (url) => {
  var domain = new URL(url).hostname;
  var ipRegex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  return ipRegex.test(domain);
}

// Check if the link have more than one double slash
const CountDSlash = (url) => {
  var cDSlash = (url.match(/\/\//g) || []).length
  return cDSlash > 1;
}

// Levenshtein distance
function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  var matrix = [];

  // Initialize the matrix
  for (var i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (var j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  // Fill in the matrix
  for (var i = 1; i <= b.length; i++) {
    for (var j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,  // Replace
          matrix[i][j - 1] + 1,      // Insert
          matrix[i - 1][j] + 1       // Delete
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

// The similarity test function is based on the Levenshtein distance
function isSimilarDomain(safeDomain, testDomain, percentage) {
  var distance = levenshteinDistance(safeDomain, testDomain);
  var maxLength = Math.max(safeDomain.length, testDomain.length);
  var similarity = 1 - distance / maxLength;

  return similarity >= percentage && similarity < 1;
}

// Check if a domain is similar with safe domain
async function checkSimilarDomain(url, percentage) {
  var domain = new URL(url).hostname;

  try {
    const filePath = chrome.runtime.getURL('src/domainLists.JSON');
    const response = await fetch(filePath);
    const data = await response.json();
    if (data.links.includes(domain)) {
      return true;
    }
    for (let i = 0; i < data.links.length; i++) {
      const safeDomain = data.links[i];
      // Check similarity and print the results
      if (isSimilarDomain(safeDomain, domain, percentage)) {
        return safeDomain; // Return true if Similarity > percentage
      }
    }
    return false;
  } catch (error) {
    console.error('Error:', error);
    return false;
  }
}

async function fetchAndCheckURLWithRegex(urlToCheck) {
  try {
    // Get hostname from url
    const urlObject = new URL(urlToCheck).hostname;

    // Get the hostname (the part without the domain extension)
    const hostname = removeDomainExtensions(urlObject);

    // Fetch the JSON file
    const jsonPath = chrome.runtime.getURL('src/domainLists.JSON');

    // Use fetch to get the contents of a JSON file
    const response = await fetch(jsonPath);
    const jsonData = await response.json();

    // Get the patterns from JSON
    if (jsonData.links.includes(urlObject)) {
      return true;
    }
    const patterns = jsonData.links.map(domain => removeDomainExtensions(domain))
    // Check each pattern with the hostname
    for (const pattern of patterns) {
      const regexPattern = new RegExp(`.*${pattern.split('').join('.*')}`);
      if (regexPattern.test(hostname) && hostname !== pattern) {
        return pattern; // If there is a match, return true
      }
    }

    return false; // If there is no match, return false
  } catch (error) {
    console.error('Error fetching or processing JSON file:', error.message);
    return false; // Returns false if an error occurs
  }
}
function removeDomainExtensions(domain) {
  const extensionsToRemove = ['.com', '.vn', '.edu', '.org', '.gov', '.ca'];
  for (const ext of extensionsToRemove) {
    if (domain.endsWith(ext)) {
      domain = domain.slice(0, -ext.length);
    }
  }
  return domain;
}

  async function fetchData(result) {
    // var domain = new URL(result).hostname;
    const url = `http://localhost:8080/check_url?url=${result}`;

  try {
    const response = await fetch(url);

    // Check if the request was successful (status code 200-299)
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    // Parse the response as JSON
    const data = await response.json();

    // Handle the JSON data
    console.log(data);

    // Data processing
    const virustotalResult = data.data.attributes.results;
    console.log("results: ", virustotalResult);

    let maliciousResult = false;

    for (const key in virustotalResult) {
      if (virustotalResult[key].hasOwnProperty("result") && virustotalResult[key].result.includes("phishing")) {
        maliciousResult = true;
        break; // If an object is found that satisfies the condition, exit the loop
      }
      if (virustotalResult[key].hasOwnProperty("result") && virustotalResult[key].result.includes("malicious")) {
        maliciousResult = true;
        break; // If an object is found that satisfies the condition, exit the loop
      }
    }
    
    return maliciousResult;
  } catch (error) {
    // Handle errors
    console.error('Error:', error);
  }
}