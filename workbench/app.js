const STORAGE_KEY = "keydeck-rk-s98-v2";
const LAYERS = ["base", "fn", "fn2", "game", "fn4", "fn5", "fn6", "fn7"];
const LAYER_LABELS = {
  base: "Base",
  fn: "Fn 1",
  fn2: "Fn 2",
  game: "Game",
  fn4: "Fn 4",
  fn5: "Fn 5",
  fn6: "Fn 6",
  fn7: "Fn 7",
};
const KEY_ROWS = [
  [
    ["Esc", "Esc", 1],
    ["F1", "F1", 1],
    ["F2", "F2", 1],
    ["F3", "F3", 1],
    ["F4", "F4", 1],
    ["F5", "F5", 1],
    ["F6", "F6", 1],
    ["F7", "F7", 1],
    ["F8", "F8", 1],
    ["F9", "F9", 1],
    ["F10", "F10", 1],
    ["F11", "F11", 1],
    ["F12", "F12", 1],
    ["Print", "Prt", 1],
    ["Scroll", "Scr", 1],
    ["Pause", "Pau", 1],
  ],
  [
    ["Tilde", "~", 1],
    ["1", "1", 1],
    ["2", "2", 1],
    ["3", "3", 1],
    ["4", "4", 1],
    ["5", "5", 1],
    ["6", "6", 1],
    ["7", "7", 1],
    ["8", "8", 1],
    ["9", "9", 1],
    ["0", "0", 1],
    ["Minus", "-", 1],
    ["Equal", "=", 1],
    ["Backspace", "Backspace", 2],
    ["Insert", "Ins", 1],
    ["Home", "Home", 1],
    ["PageUp", "PgUp", 1],
    ["NumLock", "Num", 1],
    ["NumDivide", "/", 1],
    ["NumMultiply", "*", 1],
    ["NumMinus", "-", 1],
  ],
  [
    ["Tab", "Tab", 1.5],
    ["Q", "Q", 1],
    ["W", "W", 1],
    ["E", "E", 1],
    ["R", "R", 1],
    ["T", "T", 1],
    ["Y", "Y", 1],
    ["U", "U", 1],
    ["I", "I", 1],
    ["O", "O", 1],
    ["P", "P", 1],
    ["LeftBracket", "[", 1],
    ["RightBracket", "]", 1],
    ["Backslash", "\\", 1.5],
    ["Delete", "Del", 1],
    ["End", "End", 1],
    ["PageDown", "PgDn", 1],
    ["Num7", "7", 1],
    ["Num8", "8", 1],
    ["Num9", "9", 1],
    ["NumPlus", "+", 1],
  ],
  [
    ["CapsLock", "Caps", 1.8],
    ["A", "A", 1],
    ["S", "S", 1],
    ["D", "D", 1],
    ["F", "F", 1],
    ["G", "G", 1],
    ["H", "H", 1],
    ["J", "J", 1],
    ["K", "K", 1],
    ["L", "L", 1],
    ["Semicolon", ";", 1],
    ["Quote", "'", 1],
    ["Enter", "Enter", 2.2],
    ["Num4", "4", 1],
    ["Num5", "5", 1],
    ["Num6", "6", 1],
    ["NumPlus2", "+", 1],
  ],
  [
    ["LeftShift", "Shift", 2.3],
    ["Z", "Z", 1],
    ["X", "X", 1],
    ["C", "C", 1],
    ["V", "V", 1],
    ["B", "B", 1],
    ["N", "N", 1],
    ["M", "M", 1],
    ["Comma", ",", 1],
    ["Period", ".", 1],
    ["Slash", "/", 1],
    ["RightShift", "Shift", 2.3],
    ["Up", "Up", 1],
    ["Num1", "1", 1],
    ["Num2", "2", 1],
    ["Num3", "3", 1],
    ["NumEnter", "Enter", 1],
  ],
  [
    ["LeftCtrl", "Ctrl", 1.2],
    ["LeftWin", "Win", 1.2],
    ["LeftAlt", "Alt", 1.2],
    ["Space", "Space", 5.7],
    ["RightAlt", "Alt", 1.2],
    ["Fn", "Fn", 1.1],
    ["Menu", "Menu", 1.1],
    ["RightCtrl", "Ctrl", 1.2],
    ["Left", "Left", 1],
    ["Down", "Down", 1],
    ["Right", "Right", 1],
    ["Num0", "0", 2],
    ["NumDecimal", ".", 1],
    ["NumEnter2", "Enter", 1],
  ],
];

let modelCatalog = [];
let modelLayouts = {};
let identifiedDevice = null;
let authorizedDevices = [];
let identityMatch = null;
let activePage = "device";
let currentLayer = "base";
let selectedKey = "K34";
let selectedMacroId = "";
let toastTimer = 0;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const makeId = () =>
  Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8);

function starterProfile(name) {
  return {
    id: makeId(),
    name: name || "Daily setup",
    modelCode: "022F",
    lighting: { effect: "mode:1", color: "#75D6C1", brightness: 72, speed: 55 },
    screen: { brightness: 70, clock: true, assetName: "", width: 0, height: 0 },
    knob: { rotate: "Volume", press: "Play / pause", longPress: "None" },
    connection: "USB-C",
    layers: { base: {}, fn: {}, fn2: {}, game: {} },
    macros: [
      {
        id: makeId(),
        name: "Quick reply",
        sequence: "TAP H\nWAIT 60 ms\nTAP I\nTAP ENTER",
      },
    ],
  };
}

function normalizeProfile(profile) {
  const value =
    profile && typeof profile === "object" ? profile : starterProfile();
  value.id = value.id || makeId();
  value.name =
    typeof value.name === "string" && value.name.trim()
      ? value.name.trim().slice(0, 48)
      : "Imported profile";
  value.modelCode =
    typeof value.modelCode === "string"
      ? value.modelCode.toUpperCase()
      : "022F";
  value.lighting =
    value.lighting && typeof value.lighting === "object" ? value.lighting : {};
  value.lighting.effect = String(value.lighting.effect || "mode:1");
  value.lighting.color = /^#[0-9a-f]{6}$/i.test(value.lighting.color || "")
    ? value.lighting.color.toUpperCase()
    : "#75D6C1";
  value.lighting.brightness = bounded(value.lighting.brightness, 72);
  value.lighting.speed = bounded(value.lighting.speed, 55);
  value.screen =
    value.screen && typeof value.screen === "object" ? value.screen : {};
  value.screen.brightness = bounded(value.screen.brightness, 70);
  value.screen.clock = value.screen.clock !== false;
  value.screen.assetName =
    typeof value.screen.assetName === "string"
      ? value.screen.assetName.slice(0, 180)
      : "";
  value.screen.width = bounded(value.screen.width, 0, 8192);
  value.screen.height = bounded(value.screen.height, 0, 8192);
  value.knob = value.knob && typeof value.knob === "object" ? value.knob : {};
  value.knob.rotate = String(value.knob.rotate || "Volume");
  value.knob.press = String(value.knob.press || "Play / pause");
  value.knob.longPress = String(value.knob.longPress || "None");
  value.connection = [
    "USB-C",
    "2.4 GHz",
    "Bluetooth 1",
    "Bluetooth 2",
    "Bluetooth 3",
  ].includes(value.connection)
    ? value.connection
    : "USB-C";
  value.layers =
    value.layers && typeof value.layers === "object" ? value.layers : {};
  for (const layer of LAYERS)
    if (!value.layers[layer] || typeof value.layers[layer] !== "object")
      value.layers[layer] = {};
  value.macros = Array.isArray(value.macros)
    ? value.macros
        .filter((macro) => macro && typeof macro === "object")
        .map((macro) => ({
          id: macro.id || makeId(),
          name: String(macro.name || "Untitled macro").slice(0, 48),
          sequence: String(macro.sequence || "").slice(0, 8000),
        }))
    : [];
  return value;
}

function bounded(value, fallback, max = 100) {
  const number = Number(value);
  return Number.isFinite(number)
    ? Math.max(0, Math.min(max, number))
    : fallback;
}

function loadState() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    if (parsed && Array.isArray(parsed.profiles) && parsed.profiles.length) {
      parsed.profiles = parsed.profiles.map(normalizeProfile);
      if (
        !parsed.profiles.some(
          (profile) => profile.id === parsed.activeProfileId,
        )
      )
        parsed.activeProfileId = parsed.profiles[0].id;
      return parsed;
    }
  } catch (error) {
    console.warn(
      "Could not read saved profile data; using a new local profile.",
    );
  }
  const first = starterProfile();
  return { activeProfileId: first.id, profiles: [first] };
}

const state = loadState();
const activeProfile = () =>
  state.profiles.find((profile) => profile.id === state.activeProfileId) ||
  state.profiles[0];

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("show"), 2700);
}

function saveState(message) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    if (message) showToast(message);
  } catch (error) {
    showToast(
      "Profile storage is full. Export your profile and remove large fields.",
    );
  }
}

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
}

function modelByCode(code) {
  return (
    modelCatalog.find(
      (model) => model.code.toUpperCase() === String(code || "").toUpperCase(),
    ) || null
  );
}

function selectedModel() {
  return modelByCode(activeProfile().modelCode) || modelByCode("022F");
}

function layoutForModel(model = selectedModel()) {
  return model ? modelLayouts[model.layoutId] || null : null;
}

function layerEntries(model = selectedModel()) {
  const labels = model?.features?.layers;
  return LAYERS.slice(0, Math.max(1, Math.min(labels?.length || 1, LAYERS.length))).map(
    (id, index) => ({ id, label: labels?.[index] || LAYER_LABELS[id] }),
  );
}

function modelSizeLabel(model) {
  const count = Number(model?.keyCount || 0);
  if (count >= 97 && count <= 104) return "96%";
  if (count >= 80 && count <= 89) return "TKL / 75%";
  if (count >= 70 && count <= 79) return "75%";
  if (count >= 65 && count <= 69) return "65%";
  if (count >= 59 && count <= 64) return "60%";
  return count ? `${count}-key layout` : "Layout not catalogued";
}

function deviceModelMatch(device) {
  if (!device || Number(device.vendorId) !== 0x258a)
    return { kind: "unsupported", model: null, candidates: [] };
  const pid = hex4(device.productId);
  const name = String(device.productName || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
  const nameMatches = modelCatalog.filter((model) => {
    const label = model.name.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    return label.length > 5 && name.includes(label);
  });
  if (nameMatches.length === 1)
    return { kind: "product-name", model: nameMatches[0], candidates: nameMatches };
  if (nameMatches.length > 1)
    return { kind: "product-name-family", model: null, candidates: nameMatches };

  const direct = modelByCode(pid);
  if (direct?.isDirectPid)
    return { kind: "product-id", model: direct, candidates: [direct] };

  const vid = hex4(device.vendorId);
  const candidates = modelCatalog.filter((model) => {
    const wirelessPid = model.features?.wirelessProductId;
    const wirelessVid = model.features?.wirelessVendorId;
    return wirelessPid === pid && (!wirelessVid || wirelessVid === vid);
  });
  if (candidates.length)
    return { kind: "receiver-id", model: null, candidates };
  const familyCandidates = modelCatalog.filter((model) =>
    name.split(/\s+/).includes(String(model.family).toLowerCase()),
  );
  return familyCandidates.length
    ? { kind: "product-name-family", model: null, candidates: familyCandidates }
    : { kind: "unmatched", model: null, candidates: [] };
}

function collectionKind(collection) {
  const page = Number(collection?.usagePage || 0);
  const usage = Number(collection?.usage || 0);
  if (page === 0x01 && usage === 0x06) return "keyboard";
  if (page === 0x01 && usage === 0x02) return "mouse";
  if (page === 0x0c) return "consumer control";
  if (page === 0x01 && usage === 0x80) return "system control";
  if (page >= 0xff00) return "vendor-defined";
  return `usage ${hex4(page)}:${hex4(usage)}`;
}

function renderProfileSelect() {
  const select = $("#profileSelect");
  select.replaceChildren();
  state.profiles.forEach((profile) => {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = profile.name;
    select.append(option);
  });
  select.value = state.activeProfileId;
}

function renderModelSelect() {
  const select = $("#modelSelect");
  const filter = String($("#modelFilter")?.value || "").trim().toLowerCase();
  const currentModel = selectedModel();
  select.replaceChildren();
  modelCatalog
    .filter((model) => {
      if (!filter) return true;
      return `${model.name} ${model.code} ${model.family} ${model.region}`
        .toLowerCase()
        .includes(filter);
    })
    .forEach((model) => {
    const option = document.createElement("option");
    option.value = model.code;
    option.textContent = `${model.name} · ${model.code}`;
    select.append(option);
  });
  select.value = [...select.options].some(
    (option) => option.value === currentModel?.code,
  )
    ? currentModel.code
    : "";
  const layout = layoutForModel(currentModel);
  $("#overviewLayoutCaption").textContent = currentModel
    ? `${currentModel.region} · ${modelSizeLabel(currentModel)} · ${layout?.keys?.length || 0} visual keys`
    : "Filter and choose a model profile";
  $("#selectedModelName").textContent =
    currentModel?.name || "Select a model";
  const exactProfileMatch = identityMatch?.model?.code === currentModel?.code;
  $("#deviceModelHeadline").textContent = currentModel
    ? exactProfileMatch
      ? currentModel.name
      : `Selected profile · ${currentModel.name}`
    : "Select a keyboard profile";
  $("#keyboardLayoutTitle").textContent = currentModel
    ? `${currentModel.family} · ${modelSizeLabel(currentModel)}`
    : "Keyboard layout";
  $("#keymapLayoutTitle").textContent = currentModel
    ? `${currentModel.name} · ${currentModel.region}`
    : "Select a model layout";
  const matchingOptionCount = select.options.length;
  $("#modelFilterCount").textContent = `${matchingOptionCount} of ${modelCatalog.length} models`;
}

function renderKeyboard(host) {
  if (!host) return;
  host.replaceChildren();
  const profile = activeProfile();
  const model = selectedModel();
  const layout = layoutForModel(model);
  const layoutWidth = Number(layout?.width || 0);
  const layoutHeight = Number(layout?.height || 0);
  host.classList.add("keyboard-stage");
  host.style.aspectRatio = `${layoutWidth || 1} / ${layoutHeight || 1}`;
  const keys = layout?.keys || [];
  if (!keys.some((key) => key.id === selectedKey))
    selectedKey = keys[0]?.id || "";
  keys.forEach((descriptor) => {
    const { id, label, x, y, w, h } = descriptor;
    const key = document.createElement("button");
    key.type = "button";
    key.className = "keycap";
    key.textContent = label;
    key.title = `${label} · ${id}`;
    key.dataset.key = id;
    key.style.left = `${(x / layoutWidth) * 100}%`;
    key.style.top = `${(y / layoutHeight) * 100}%`;
    key.style.width = `${(w / layoutWidth) * 100}%`;
    key.style.height = `${(h / layoutHeight) * 100}%`;
    const mapping = profile.layers[currentLayer][id];
    if (mapping && mapping.type !== "Default") key.classList.add("mapped");
    if (/shift|ctrl|alt|win|caps|tab|enter|backspace|space|fn/i.test(label))
      key.classList.add("modifier");
    if (id === selectedKey && activePage === "keys")
      key.classList.add("selected");
    if (mapping && mapping.type !== "Default")
      key.title = `${label} → ${mapping.value || mapping.type}`;
    key.addEventListener("click", () => {
      selectedKey = id;
      if (host.id === "keymapKeyboard") return renderAll();
      setPage("keys");
      renderAll();
    });
    host.append(key);
  });
}

function renderLighting() {
  const model = selectedModel();
  const features = model?.features || {};
  const lighting = activeProfile().lighting;
  const effectSelect = $("#effectSelect");
  const slots = features.lightingModeSlots || [];
  effectSelect.replaceChildren();
  slots.forEach((slot) => {
    const option = document.createElement("option");
    option.value = `mode:${slot}`;
    option.textContent = `Mode slot ${slot}`;
    effectSelect.append(option);
  });
  if (lighting.effect && ![...effectSelect.options].some((option) => option.value === lighting.effect)) {
    const legacy = document.createElement("option");
    legacy.value = lighting.effect;
    legacy.textContent = `Saved label: ${lighting.effect}`;
    effectSelect.append(legacy);
  }
  effectSelect.value = lighting.effect;
  effectSelect.disabled = !features.rgb || !slots.length;
  $("#lightingModeInfo").textContent = features.rgb
    ? `${slots.length} lighting mode slots are listed for this profile. Mode names are not decoded, and values stay local.`
    : "The installed RK profile does not list RGB backlighting for this model.";
  $("#lightingFeatureState").textContent = features.rgb
    ? `${slots.length} mode slots · profile only`
    : "No RGB profile";
  $("#quickLightingControl").hidden = !features.rgb;
  $("#quickEffectControl").hidden = !features.rgb;
  $("#colorPicker").disabled = !features.rgb;
  $("#brightnessRange").disabled = !features.rgb;
  $("#speedRange").disabled = !features.rgb;
  $("#quickBrightness").disabled = !features.rgb;
  $$(".swatch").forEach((swatch) => (swatch.disabled = !features.rgb));
  $("#colorPicker").value = lighting.color;
  $("#colorHex").textContent = lighting.color;
  $("#brightnessRange").value = lighting.brightness;
  $("#brightnessValue").textContent = lighting.brightness + "%";
  $("#quickBrightness").value = lighting.brightness;
  $("#overviewBrightness").textContent = lighting.brightness + "%";
  $("#speedRange").value = lighting.speed;
  $("#speedValue").textContent = lighting.speed + "%";
  $("#overviewEffect").textContent = lighting.effect.startsWith("mode:")
    ? `Slot ${lighting.effect.slice(5)}`
    : `Saved: ${lighting.effect}`;
  $("#saveLighting").disabled = !features.rgb;
  $$(".swatch").forEach((swatch) =>
    swatch.classList.toggle(
      "active",
      swatch.dataset.color.toUpperCase() === lighting.color.toUpperCase(),
    ),
  );
}

function renderEditor() {
  const profile = activeProfile();
  const model = selectedModel();
  const layout = layoutForModel(model);
  const layers = layerEntries(model);
  const layerSelect = $("#layerSelect");
  layerSelect.replaceChildren();
  layers.forEach(({ id, label }) => {
    const option = document.createElement("option");
    option.value = id;
    option.textContent = label;
    layerSelect.append(option);
  });
  if (!layers.some(({ id }) => id === currentLayer)) currentLayer = "base";
  layerSelect.value = currentLayer;
  const mapping = profile.layers[currentLayer][selectedKey];
  const descriptor = layout?.keys?.find((key) => key.id === selectedKey);
  const label = descriptor?.label || selectedKey;
  $("#selectedKeyName").textContent = label;
  $("#selectedKeycap").textContent = label;
  $("#selectedLayerName").textContent =
    layers.find(({ id }) => id === currentLayer)?.label || LAYER_LABELS[currentLayer];
  $("#actionSelect").value = mapping?.type || "Default";
  $("#actionValue").value = mapping?.value || label;
  $("#actionValueWrap").hidden =
    !mapping || !["Custom", "Macro", "Media"].includes(mapping.type);
  const count = Object.keys(profile.layers[currentLayer]).length;
  $("#layerSelectCaption").textContent =
    `${layers.length} layer${layers.length === 1 ? "" : "s"} in this model profile`;
  $("#mappingCount").textContent = count
    ? count +
      " remap" +
      (count === 1 ? "" : "s") +
      " in " +
      LAYER_LABELS[currentLayer]
    : "No remaps in " + LAYER_LABELS[currentLayer];
}

function renderScreen() {
  const model = selectedModel();
  const screenSpec = model?.features?.screen;
  const screen = activeProfile().screen;
  $("#screenBrightness").value = screen.brightness;
  $("#screenBrightnessValue").textContent = screen.brightness + "%";
  $("#screenClock").checked = screen.clock;
  const asset = screen.assetName;
  $("#screenAssetState").textContent = asset || "No display asset selected";
  $("#screenAssetName").textContent = asset || "Choose PNG, JPG or GIF";
  $("#screenAssetDimensions").textContent = asset
    ? screen.width + " × " + screen.height + " pixels · metadata only"
    : "Files are inspected locally in your browser.";
  $("#screenTransferTitle").textContent = asset || "No display asset selected";
  $("#screenTransferText").textContent = asset
    ? "Asset metadata is stored in this profile. The image file stays on this PC and has not been transferred."
    : "Asset metadata stays local. The image is not uploaded and is not sent to the keyboard.";
  $("#screenPageTitle").textContent = screenSpec
    ? `${screenSpec.width} × ${screenSpec.height} display settings`
    : "No display in this profile";
  $("#screenOverviewSize").textContent = screenSpec
    ? `${screenSpec.width} × ${screenSpec.height}`
    : "No display listed";
  $("#screenPageDescription").textContent = screenSpec
    ? `Store display preferences for ${model.name}. Assets stay on this PC; no data is sent to the keyboard.`
    : "The installed RK profile does not list a screen for this model.";
  $("#screenSpecBadge").textContent = screenSpec
    ? `${screenSpec.width} × ${screenSpec.height}${screenSpec.maxFrames ? ` · ${screenSpec.maxFrames} frame cap` : ""}`
    : "NO DISPLAY PROFILE";
  $("#screenResolution").textContent = screenSpec
    ? `${screenSpec.width} × ${screenSpec.height}`
    : "Not listed";
  $("#screenFrameLimit").textContent = screenSpec?.maxFrames
    ? `${screenSpec.maxFrames} frames`
    : "Not listed";
  $("#screenFeatureCard").hidden = !screenSpec;
  $("#page-screen").hidden = !screenSpec;
  $("#screenNavButton").hidden = !screenSpec;
  $("#screenTransport").textContent = identifiedDevice
    ? "Descriptor only · no report opened"
    : "No device selected";
  $("#saveScreen").disabled = !screenSpec;
}

function renderKnob() {
  const profile = activeProfile();
  const model = selectedModel();
  const hasDial = model?.family === "S98";
  const modes = connectionChoices(model);
  $("#knobControls").hidden = !hasDial;
  $("#knobHardwareLabel").textContent = hasDial
    ? "Rotary dial preferences"
    : "No dial control is listed for this model";
  $("#connectionMode").replaceChildren();
  modes.forEach((mode) => {
    const option = document.createElement("option");
    option.value = mode.value;
    option.textContent = mode.label;
    $("#connectionMode").append(option);
  });
  const modeCards = $("#connectionModeCards");
  modeCards.replaceChildren();
  modes.forEach((mode) => {
    const card = document.createElement("div");
    const active = mode.value === profile.connection;
    card.innerHTML = `<strong>${escapeHtml(mode.label)}</strong><small>${active ? "Selected profile value" : "Profile option"}</small>`;
    modeCards.append(card);
  });
  const selectedMode = modes.some((mode) => mode.value === profile.connection)
    ? profile.connection
    : modes[0]?.value || "USB-C";
  $("#knobRotate").value = profile.knob.rotate;
  $("#knobPress").value = profile.knob.press;
  $("#knobLongPress").value = profile.knob.longPress;
  $("#connectionMode").value = selectedMode;
  $("#connectionModeState").textContent = modes.length > 1
    ? `${modes.length} profile preferences · no physical mode switch`
    : "Only USB identity is listed for this model";
  $("#connectionFeatureSummary").textContent = modes.length > 1
    ? modes.slice(1).map((mode) => mode.label).join(" · ")
    : "USB identity only · other modes unknown";
  $("#triModeCard").hidden = modes.length < 2;
  $("#smartDisplayFeature").hidden = !model?.features?.screen;
  $("#rotaryFeature").hidden = !hasDial;
  $("#saveKnob").disabled = !hasDial;
}

function connectionChoices(model) {
  if (model?.family === "S98")
    return [
      { value: "USB-C", label: "USB-C wired" },
      { value: "2.4 GHz", label: "2.4 GHz receiver" },
      { value: "Bluetooth 1", label: "Bluetooth slot 1" },
      { value: "Bluetooth 2", label: "Bluetooth slot 2" },
      { value: "Bluetooth 3", label: "Bluetooth slot 3" },
    ];
  const name = String(model?.name || "").toLowerCase();
  const modes = [{ value: "USB-C", label: "USB wired" }];
  if (/three.?mode|tri.?mode|3.?mode/.test(name)) {
    modes.push(
      { value: "2.4 GHz", label: "2.4 GHz receiver" },
      { value: "Bluetooth 1", label: "Bluetooth" },
    );
  } else if (model?.features?.wirelessProductId) {
    modes.push({ value: "2.4 GHz", label: "Wireless receiver (catalog PID)" });
  } else if (/bluetooth|\bbt\b/.test(name)) {
    modes.push({ value: "Bluetooth 1", label: "Bluetooth" });
  }
  return modes;
}

function migrateLegacyMappings() {
  let changed = false;
  const aliases = {
    Tilde: ["`", "~"],
    Print: ["PrtSc", "Print"],
    Scroll: ["ScrLock", "Scroll", "Scr"],
    Pause: ["Pause", "Pau"],
    Insert: ["Insert", "Ins"],
    PageUp: ["PgUp"],
    PageDown: ["PgDn"],
    NumDivide: ["Num /", "Num/"],
    NumMultiply: ["Num*", "Num *"],
    NumMinus: ["Num-"],
    NumPlus: ["Num+"],
    NumPlus2: ["Num+"],
    NumDecimal: ["Num .", "Num."],
    LeftShift: ["LShift"],
    RightShift: ["RShift"],
    LeftCtrl: ["LCtrl"],
    RightCtrl: ["RCtrl"],
    LeftWin: ["LWin"],
    LeftAlt: ["LAlt"],
    RightAlt: ["RAlt"],
    Fn: ["FN", "Fn"],
    Menu: ["App", "Menu"],
  };
  state.profiles.forEach((profile) => {
    const layout = layoutForModel(modelByCode(profile.modelCode));
    if (!layout?.keys?.length) return;
    const keysByLabel = new Map();
    layout.keys.forEach((key) => {
      const normalized = key.label.toLowerCase().replace(/\s+/g, "").trim();
      if (!keysByLabel.has(normalized)) keysByLabel.set(normalized, []);
      keysByLabel.get(normalized).push(key);
    });
    Object.values(profile.layers).forEach((layerMap) => {
      Object.entries(layerMap).forEach(([oldId, mapping]) => {
        if (layout.keys.some((key) => key.id === oldId)) return;
        const legacy = KEY_ROWS.flat().find(([id]) => id === oldId);
        if (!legacy) return;
        const labels = aliases[oldId] || [legacy[1]];
        const candidates = labels.flatMap((label) =>
          keysByLabel.get(label.toLowerCase().replace(/\s+/g, "").trim()) || [],
        );
        if (!candidates.length) return;
        let target = candidates[0];
        if (/^Num/.test(oldId)) target = candidates.find((key) => /^Num/i.test(key.label)) || candidates.at(-1);
        if (oldId === "NumEnter" || oldId === "NumEnter2")
          target = candidates.find((key) => key.x > layout.width * 0.82) || candidates.at(-1);
        if (layerMap[target.id]) return;
        layerMap[target.id] = mapping;
        delete layerMap[oldId];
        changed = true;
      });
    });
  });
  if (changed) saveState();
}

function renderMacros() {
  const list = $("#macroList");
  list.replaceChildren();
  const profile = activeProfile();
  const macroBuffers = selectedModel()?.features?.macroBuffers || 0;
  $("#macroCapability").textContent = macroBuffers
    ? `This RK profile lists ${macroBuffers} macro buffers. The workbench keeps sequences local and does not write them.`
    : "This model profile does not specify macro buffer capacity. Sequences remain local in the workbench.";
  if (!profile.macros.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No macros in this profile. Add one to begin.";
    list.append(empty);
  }
  if (!profile.macros.some((macro) => macro.id === selectedMacroId))
    selectedMacroId = profile.macros[0]?.id || "";
  for (const macro of profile.macros) {
    const item = document.createElement("button");
    item.type = "button";
    item.className =
      "macro-list-item" + (macro.id === selectedMacroId ? " active" : "");
    item.innerHTML =
      "<strong>" +
      escapeHtml(macro.name) +
      "</strong><small>" +
      macro.sequence.split(/\r?\n/).filter(Boolean).length +
      " steps</small>";
    item.addEventListener("click", () => {
      selectedMacroId = macro.id;
      renderMacros();
    });
    list.append(item);
  }
  const selected = profile.macros.find((macro) => macro.id === selectedMacroId);
  $("#macroName").value = selected?.name || "";
  $("#macroSequence").value = selected?.sequence || "";
  $("#deleteMacro").disabled = !selected;
}

function renderProfiles() {
  const grid = $("#profileGrid");
  grid.replaceChildren();
  $("#profileCount").textContent =
    state.profiles.length +
    " profile" +
    (state.profiles.length === 1 ? "" : "s");
  state.profiles.forEach((profile) => {
    const model = modelByCode(profile.modelCode);
    const card = document.createElement("article");
    card.className =
      "profile-card" + (profile.id === state.activeProfileId ? " active" : "");
    card.innerHTML =
      "<div class='profile-card-top'><span class='profile-card-icon'>RK</span>" +
      (profile.id === state.activeProfileId
        ? "<span class='active-badge'>ACTIVE</span>"
        : "") +
      "</div><h3>" +
      escapeHtml(profile.name) +
      "</h3><p>" +
      escapeHtml(model?.name || "RK model profile") +
      " · " +
      profile.macros.length +
      " macros</p><div class='profile-card-actions'><button class='button button-light' data-activate='" +
      escapeHtml(profile.id) +
      "'>" +
      (profile.id === state.activeProfileId ? "Current" : "Use profile") +
      "</button><button class='button button-light' data-rename='" +
      escapeHtml(profile.id) +
      "'>Rename</button>" +
      (state.profiles.length > 1
        ? "<button class='button button-light' data-delete='" +
          escapeHtml(profile.id) +
          "'>Delete</button>"
        : "") +
      "</div>";
    grid.append(card);
  });
  $$("[data-activate]").forEach((button) =>
    button.addEventListener("click", () => {
      state.activeProfileId = button.dataset.activate;
      currentLayer = "base";
      selectedMacroId = "";
      saveState("Profile switched.");
      renderAll();
    }),
  );
  $$("[data-rename]").forEach((button) =>
    button.addEventListener("click", () => {
      const profile = state.profiles.find(
        (entry) => entry.id === button.dataset.rename,
      );
      const name = profile && prompt("Profile name", profile.name);
      if (name?.trim()) {
        profile.name = name.trim();
        saveState("Profile renamed.");
        renderAll();
      }
    }),
  );
  $$("[data-delete]").forEach((button) =>
    button.addEventListener("click", () => {
      const profile = state.profiles.find(
        (entry) => entry.id === button.dataset.delete,
      );
      if (!profile || !confirm("Delete profile '" + profile.name + "'?"))
        return;
      state.profiles = state.profiles.filter(
        (entry) => entry.id !== profile.id,
      );
      if (state.activeProfileId === profile.id)
        state.activeProfileId = state.profiles[0].id;
      saveState("Profile deleted.");
      renderAll();
    }),
  );
}

function setDeviceStatus(device) {
  identifiedDevice = device || null;
  const connected = Boolean(device);
  identityMatch = connected ? deviceModelMatch(device) : null;
  const match = identityMatch;
  if (match?.model && activeProfile().modelCode !== match.model.code) {
    activeProfile().modelCode = match.model.code;
    saveState();
  }
  const lampText = connected ? "RK HID device detected" : "No keyboard detected";
  $("#sidebarDeviceState").textContent = lampText;
  $("#sidebarDeviceName").textContent = match?.model?.name || descriptorName(device) || deviceIdLabel(device) || "Choose a model";
  $("#sidebarDeviceId").textContent = connected
    ? `VID:PID ${hex4(device.vendorId)}:${hex4(device.productId)} · descriptor only`
    : "USB device access is off";
  $("#devicePillText").textContent = connected
    ? match?.model?.name || "RK keyboard detected · model unresolved"
    : "Not identified";
  $("#deviceIdentity").textContent = connected
    ? "Browser permission granted. This app reads the USB/HID descriptor only; HID reports are not opened or exchanged."
    : "Identify a keyboard to inspect its USB identity. The app will not open or exchange HID reports.";
  $("#deviceIdValue").textContent = connected
    ? hex4(device.vendorId) + ":" + hex4(device.productId)
    : "—";
  $("#diagName").textContent = connected
    ? descriptorName(device) || "Unavailable (invalid descriptor text)"
    : "Not identified";
  $("#diagVendor").textContent = connected ? "0x" + hex4(device.vendorId) : "—";
  $("#diagProduct").textContent = connected
    ? "0x" + hex4(device.productId)
    : "—";
  $("#diagCollections").textContent = connected
    ? String(device.collections?.length || 0)
    : "—";
  $("#diagCollectionTypes").textContent = connected
    ? [...new Set((device.collections || []).map(collectionKind))].join(", ") || "Not reported"
    : "—";
  $$("#sidebarLamp,#deviceLamp").forEach((lamp) =>
    lamp.classList.toggle("connected", connected),
  );
  const callout = $("#supportCallout");
  const method = match?.kind === "product-id"
    ? "USB product ID"
    : match?.kind === "product-name"
      ? "USB product name"
      : "";
  if (!connected) {
    $("#diagProfile").textContent = "None";
    callout.innerHTML =
      "<strong>No device access granted</strong><p>Identify a keyboard to compare its descriptors with the 188 model profiles in this project.</p>";
  } else if (match?.model) {
    $("#diagProfile").textContent = `${match.model.name} · ${method}`;
    callout.innerHTML =
      `<strong>Model match: ${escapeHtml(match.model.name)}</strong><p>Matched by ${escapeHtml(method)} against profile ${escapeHtml(match.model.code)}. The app has not opened a HID report.</p>`;
  } else if (match?.candidates?.length) {
    const shown = match.candidates.slice(0, 4).map((model) => model.name);
    const names = shown.join(", ") +
      (match.candidates.length > shown.length ? ` and ${match.candidates.length - shown.length} more` : "");
    const reason = match.kind === "receiver-id"
      ? `Product ID 0x${hex4(device.productId)} is listed as a receiver ID for ${escapeHtml(names)}. Receiver IDs can be shared.`
      : `The device name is not specific enough to distinguish ${escapeHtml(names)}.`;
    $("#diagProfile").textContent = "Several model profiles";
    callout.innerHTML =
      `<strong>RK keyboard detected; model is not unique</strong><p>${reason} Choose the correct model profile below; the app will show its layout without probing the keyboard.</p>`;
  } else {
    $("#diagProfile").textContent = "No catalog match";
    callout.innerHTML =
      "<strong>RK keyboard detected; model unresolved</strong><p>This USB identity does not uniquely match the installed model catalog. Choose the correct model profile to display its layout. No report probe was run.</p>";
  }
  $("#lightingDeviceState").textContent = connected
    ? `${hex4(device.vendorId)}:${hex4(device.productId)}`
    : "Not identified";
  $("#deviceModelState").textContent = match?.model
    ? `${match.model.name} · matched by ${method}`
    : connected
      ? "Model unresolved · choose a profile below"
      : "No keyboard selected";
  renderAuthorizedDevices();
  $("#screenTransport").textContent = connected
    ? "Descriptor only · no report opened"
    : "Not connected";
  if (device)
    window.localStorage.setItem(
      "keydeck-last-device",
      hex4(device.vendorId) + ":" + hex4(device.productId),
    );
  renderScreen();
}

function hex4(number) {
  return Number(number).toString(16).padStart(4, "0").toUpperCase();
}

function descriptorName(device) {
  const name = String(device?.productName || "").trim();
  // WebHID product names can be malformed on some receivers. Keep those bytes
  // out of the UI and avoid presenting mojibake as a model identification.
  return /^[\x20-\x7E]{2,80}$/.test(name) ? name : "";
}

function deviceIdLabel(device) {
  return device
    ? `RK HID device ${hex4(device.vendorId)}:${hex4(device.productId)}`
    : "";
}

async function identifyDevice() {
  if (!navigator.hid) {
    showToast(
      "WebHID is unavailable here. Use a recent desktop Chrome or Edge browser over HTTPS or localhost.",
    );
    return;
  }
  try {
    const devices = await navigator.hid.requestDevice({
      filters: [{ vendorId: 0x258a }],
    });
    if (!devices.length) return;
    authorizedDevices = [
      ...new Map(
        [...authorizedDevices, ...devices].map((device) => [deviceKey(device), device]),
      ).values(),
    ];
    setDeviceStatus(devices[0]);
    renderAll();
    showToast(identityMatch?.model
      ? `${identityMatch.model.name} matched from the USB descriptor.`
      : "RK keyboard identified. Choose a model profile; no HID report was opened.");
  } catch (error) {
    if (error && error.name === "NotFoundError") return;
    showToast("The browser could not identify that device.");
  }
}

function deviceKey(device) {
  return `${device.vendorId}:${device.productId}:${device.productName || ""}:${device.serialNumber || ""}`;
}

function renderAuthorizedDevices() {
  const select = $("#deviceSelect");
  const wrap = $("#deviceSelectWrap");
  if (!select || !wrap) return;
  select.replaceChildren();
  authorizedDevices.forEach((device, index) => {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = `${descriptorName(device) || "RK HID device"} · ${hex4(device.vendorId)}:${hex4(device.productId)}`;
    select.append(option);
  });
  wrap.hidden = authorizedDevices.length < 2;
  const activeIndex = authorizedDevices.findIndex(
    (device) => deviceKey(device) === (identifiedDevice && deviceKey(identifiedDevice)),
  );
  if (activeIndex >= 0) select.value = String(activeIndex);
}

async function scanAuthorizedDevices() {
  if (!navigator.hid?.getDevices) return;
  try {
    authorizedDevices = (await navigator.hid.getDevices()).filter(
      (device) => device.vendorId === 0x258a,
    );
    if (authorizedDevices.length) setDeviceStatus(authorizedDevices[0]);
    else setDeviceStatus(null);
    renderAll();
  } catch (error) {
    console.warn("Could not inspect previously authorized HID descriptors.");
  }
}

function renderAll() {
  state.profiles = state.profiles.map(normalizeProfile);
  const model = selectedModel();
  if (model && !layerEntries(model).some(({ id }) => id === currentLayer))
    currentLayer = "base";
  renderProfileSelect();
  renderModelSelect();
  renderModelFeatures();
  renderKeyboard($("#deviceKeyboard"));
  renderKeyboard($("#keymapKeyboard"));
  renderLighting();
  renderEditor();
  renderScreen();
  renderKnob();
  renderMacros();
  renderProfiles();
  if (identifiedDevice) setDeviceStatus(identifiedDevice);
}

function renderModelFeatures() {
  const model = selectedModel();
  const features = model?.features || {};
  const summary = $("#modelFeatureSummary");
  summary.replaceChildren();
  const items = [
    `${model?.keyCount || "?"} key profile`,
    `${features.layers?.length || 1} layer${features.layers?.length === 1 ? "" : "s"}`,
  ];
  if (features.rgb)
    items.push(`${features.lightingModeSlots?.length || 0} RGB mode slots`);
  if (features.screen)
    items.push(`Display ${features.screen.width} × ${features.screen.height}`);
  if (features.macroBuffers)
    items.push(`${features.macroBuffers} macro buffers`);
  if (features.wirelessProductId)
    items.push(`Receiver ID ${features.wirelessProductId}`);
  if (model?.family === "S98") items.push("Rotary dial");
  items.forEach((text) => {
    const chip = document.createElement("span");
    chip.className = "feature-chip";
    chip.textContent = text;
    summary.append(chip);
  });
  $("#lightingNavButton").disabled = !features.rgb;
  $("#lightingNavButton").title = features.rgb
    ? "Edit local lighting preferences"
    : "No RGB backlight is listed for this model";
  if (!features.screen && activePage === "screen") setPage("device");
  if (!features.rgb && activePage === "lighting") setPage("device");
}

function setPage(page) {
  const model = selectedModel();
  if (page === "screen" && !model?.features?.screen) {
    showToast("This model profile does not list a keyboard display.");
    page = "device";
  }
  if (page === "lighting" && !model?.features?.rgb) {
    showToast("This model profile does not list RGB backlighting.");
    page = "device";
  }
  activePage = page;
  $$(".page").forEach((section) =>
    section.classList.toggle("active", section.id === "page-" + page),
  );
  $$(".nav-item").forEach((button) =>
    button.classList.toggle("active", button.dataset.page === page),
  );
  const titles = {
    device: "Device",
    keys: "Key map",
    lighting: "Lighting",
    screen: "Smart display",
    knob: "Controls & modes",
    macros: "Macros",
    profiles: "Profiles",
    diagnostics: "Device info",
  };
  $("#crumbTitle").textContent = titles[page] || "Device";
}

function downloadJson(filename, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function addProfile() {
  const name = prompt(
    "Name this profile",
    "Profile " + (state.profiles.length + 1),
  );
  if (!name?.trim()) return;
  const profile = starterProfile(name.trim());
  state.profiles.push(profile);
  state.activeProfileId = profile.id;
  saveState("Profile created.");
  renderAll();
}

function saveMacro() {
  const profile = activeProfile();
  const macro = profile.macros.find((entry) => entry.id === selectedMacroId);
  if (!macro) return showToast("Create a macro first.");
  macro.name = $("#macroName").value.trim() || "Untitled macro";
  macro.sequence = $("#macroSequence").value.slice(0, 8000);
  saveState("Macro saved to this profile.");
  renderMacros();
}

function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  if (lines.length < 2) return [];
  const headers = lines
    .shift()
    .split(",")
    .map((header) => header.trim().toLowerCase());
  return lines.map((line) => {
    const values = line.split(",");
    return Object.fromEntries(
      headers.map((header, index) => [header, (values[index] || "").trim()]),
    );
  });
}

async function importTrace(file) {
  if (!file) return;
  try {
    const text = await file.text();
    const parsed = file.name.toLowerCase().endsWith(".json")
      ? JSON.parse(text.replace(/^\uFEFF/, ""))
      : parseCsv(text);
    const records = Array.isArray(parsed)
      ? parsed
      : parsed.records || parsed.packets || parsed.events || [];
    $("#traceSummary").textContent = records.length + " records · " + file.name;
    const body = $("#traceRows");
    body.replaceChildren();
    records.slice(0, 300).forEach((record) => {
      const row = document.createElement("tr");
      [
        record.time || record.timestamp || record.frame || "—",
        record.direction || record.type || record.transfer || "—",
        record.reportId || record.report_id || record.endpoint || "—",
        record.data || record.bytes || record.payload || "—",
      ].forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = String(value).slice(0, 150);
        row.append(cell);
      });
      body.append(row);
    });
    if (!records.length)
      body.innerHTML =
        '<tr><td colspan="4" class="table-empty">No records were found.</td></tr>';
    if (records.length > 300) showToast("Showing the first 300 records.");
  } catch (error) {
    showToast("Could not parse that file as a trace CSV or JSON list.");
  }
}

function wireEvents() {
  $$("[data-page]").forEach((button) =>
    button.addEventListener("click", () => setPage(button.dataset.page)),
  );
  $$("[data-go]").forEach((button) =>
    button.addEventListener("click", () => setPage(button.dataset.go)),
  );
  $$("[data-identify]").forEach((button) =>
    button.addEventListener("click", identifyDevice),
  );
  $("#profileSelect").addEventListener("change", (event) => {
    state.activeProfileId = event.target.value;
    currentLayer = "base";
    selectedMacroId = "";
    saveState("Profile switched.");
    renderAll();
  });
  $("#modelSelect").addEventListener("change", (event) => {
    if (!event.target.value) return;
    activeProfile().modelCode = event.target.value;
    saveState("Model profile saved.");
    renderAll();
  });
  $("#modelFilter").addEventListener("input", renderModelSelect);
  $("#deviceSelect").addEventListener("change", (event) => {
    const device = authorizedDevices[Number(event.target.value)];
    if (device) {
      setDeviceStatus(device);
      renderAll();
    }
  });
  $("#layerSelect").addEventListener("change", (event) => {
    currentLayer = event.target.value;
    renderAll();
  });
  $("#actionSelect").addEventListener("change", () => {
    $("#actionValueWrap").hidden = !["Custom", "Macro", "Media"].includes(
      $("#actionSelect").value,
    );
  });
  $("#saveKeyMapping").addEventListener("click", () => {
    const type = $("#actionSelect").value;
    if (type === "Default")
      delete activeProfile().layers[currentLayer][selectedKey];
    else
      activeProfile().layers[currentLayer][selectedKey] = {
        type,
        value: ["Custom", "Macro", "Media"].includes(type)
          ? $("#actionValue").value.trim()
          : "",
      };
    saveState("Key assignment saved to this profile.");
    renderAll();
  });
  $("#clearKeyMapping").addEventListener("click", () => {
    delete activeProfile().layers[currentLayer][selectedKey];
    saveState("Key assignment reset.");
    renderAll();
  });
  $("#effectSelect").addEventListener("change", (event) => {
    activeProfile().lighting.effect = event.target.value;
    saveState();
    renderAll();
  });
  $("#colorPicker").addEventListener("input", (event) => {
    activeProfile().lighting.color = event.target.value.toUpperCase();
    saveState();
    renderLighting();
  });
  $("#colorSwatches").addEventListener("click", (event) => {
    const swatch = event.target.closest("[data-color]");
    if (swatch) {
      activeProfile().lighting.color = swatch.dataset.color.toUpperCase();
      saveState();
      renderLighting();
    }
  });
  const setBrightness = (value) => {
    activeProfile().lighting.brightness = Number(value);
    saveState();
    renderLighting();
  };
  $("#brightnessRange").addEventListener("input", (event) =>
    setBrightness(event.target.value),
  );
  $("#quickBrightness").addEventListener("input", (event) =>
    setBrightness(event.target.value),
  );
  $("#speedRange").addEventListener("input", (event) => {
    activeProfile().lighting.speed = Number(event.target.value);
    saveState();
    renderLighting();
  });
  $("#saveLighting").addEventListener("click", () =>
    showToast("Lighting values saved. Device output is locked."),
  );
  $("#screenBrightness").addEventListener("input", (event) => {
    activeProfile().screen.brightness = Number(event.target.value);
    saveState();
    renderScreen();
  });
  $("#screenClock").addEventListener("change", (event) => {
    activeProfile().screen.clock = event.target.checked;
    saveState();
  });
  $("#screenFile").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const bitmap = await createImageBitmap(file);
      activeProfile().screen.assetName = file.name.slice(0, 180);
      activeProfile().screen.width = bitmap.width;
      activeProfile().screen.height = bitmap.height;
      bitmap.close();
      saveState("Image dimensions saved. Image data was not uploaded.");
      renderScreen();
    } catch (error) {
      showToast("Could not inspect that image. Try PNG, JPG or GIF.");
    }
    event.target.value = "";
  });
  $("#saveScreen").addEventListener("click", () =>
    showToast(
      "Display profile saved. The image has not been sent to the keyboard.",
    ),
  );
  $("#knobRotate").addEventListener("change", (event) => {
    activeProfile().knob.rotate = event.target.value;
    saveState();
  });
  $("#knobPress").addEventListener("change", (event) => {
    activeProfile().knob.press = event.target.value;
    saveState();
  });
  $("#knobLongPress").addEventListener("change", (event) => {
    activeProfile().knob.longPress = event.target.value;
    saveState();
  });
  $("#connectionMode").addEventListener("change", (event) => {
    activeProfile().connection = event.target.value;
    saveState("Connection preference saved to profile.");
  });
  $("#saveKnob").addEventListener("click", () =>
    showToast("Knob profile saved. Physical settings were not changed."),
  );
  $("#newMacro").addEventListener("click", () => {
    const macro = {
      id: makeId(),
      name: "New macro",
      sequence: "TAP W\nWAIT 40 ms\nTAP ENTER",
    };
    activeProfile().macros.push(macro);
    selectedMacroId = macro.id;
    saveState("Macro created.");
    renderMacros();
  });
  $("#saveMacro").addEventListener("click", saveMacro);
  $("#deleteMacro").addEventListener("click", () => {
    if (!selectedMacroId) return;
    activeProfile().macros = activeProfile().macros.filter(
      (macro) => macro.id !== selectedMacroId,
    );
    selectedMacroId = activeProfile().macros[0]?.id || "";
    saveState("Macro deleted.");
    renderMacros();
  });
  $("#newProfile").addEventListener("click", addProfile);
  $("#duplicateProfile").addEventListener("click", () => {
    const copy = normalizeProfile(JSON.parse(JSON.stringify(activeProfile())));
    copy.id = makeId();
    copy.name = activeProfile().name + " copy";
    state.profiles.push(copy);
    state.activeProfileId = copy.id;
    selectedMacroId = "";
    saveState("Profile duplicated.");
    renderAll();
  });
  $("#saveProfileButton").addEventListener("click", () => {
    saveState("Profile saved on this device.");
    renderAll();
  });
  $("#exportActive").addEventListener("click", () => {
    const name =
      activeProfile()
        .name.toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "") || "profile";
    downloadJson("keydeck-" + name + ".json", {
      format: "keydeck-rk-profile-v2",
      profile: activeProfile(),
    });
  });
  $("#importProfileButton").addEventListener("click", () =>
    $("#profileFile").click(),
  );
  $("#profileFile").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const parsed = JSON.parse((await file.text()).replace(/^\uFEFF/, ""));
      const imported = normalizeProfile(parsed.profile || parsed);
      imported.id = makeId();
      imported.name = imported.name + " import";
      state.profiles.push(imported);
      state.activeProfileId = imported.id;
      saveState("Profile imported locally.");
      renderAll();
    } catch (error) {
      showToast("That file is not a valid profile JSON.");
    }
    event.target.value = "";
  });
  $("#traceFile").addEventListener("change", (event) =>
    importTrace(event.target.files?.[0]),
  );
  $("#writeChanges").addEventListener("click", () =>
    showToast("Hardware writes are disabled in this release."),
  );
  if (navigator.hid)
    {
      navigator.hid.addEventListener("connect", (event) => {
        if (event.device.vendorId !== 0x258a) return;
        if (!authorizedDevices.some((device) => deviceKey(device) === deviceKey(event.device)))
          authorizedDevices.push(event.device);
        setDeviceStatus(event.device);
        renderAll();
      });
      navigator.hid.addEventListener("disconnect", (event) => {
        authorizedDevices = authorizedDevices.filter(
          (device) => deviceKey(device) !== deviceKey(event.device),
        );
        if (identifiedDevice && deviceKey(event.device) === deviceKey(identifiedDevice)) {
          const next = authorizedDevices[0] || null;
          setDeviceStatus(next);
          renderAll();
          showToast(next ? "Selected the next authorized RK device." : "Keyboard disconnected.");
        } else {
          renderAuthorizedDevices();
        }
      });
    }
}

async function loadModelCatalog() {
  try {
    const response = await fetch("models.json", { cache: "no-store" });
    if (!response.ok) throw new Error("catalog unavailable");
    const catalog = await response.json();
    modelCatalog = Array.isArray(catalog) ? catalog : catalog.models || [];
    modelLayouts = Array.isArray(catalog) ? {} : catalog.layouts || {};
  } catch (error) {
    modelCatalog = [];
    modelLayouts = {};
  }
  migrateLegacyMappings();
  renderAll();
  scanAuthorizedDevices();
}

wireEvents();
renderAll();
loadModelCatalog();
