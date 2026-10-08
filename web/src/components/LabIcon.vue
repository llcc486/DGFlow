<script setup>
defineProps({ name: { type: String, default: 'grid' }, size: { type: [String, Number], default: 20 } })
const paths = {
  grid: ['M3 3h7v7H3z', 'M14 3h7v7h-7z', 'M3 14h7v7H3z', 'M14 14h7v7h-7z'],
  nodes: ['M12 8V4', 'M5 16v-4h14v4', 'M12 12V8', 'M9 2h6v6H9z', 'M2 16h6v6H2z', 'M16 16h6v6h-6z'],
  shield: ['M12 3 3.5 6v6c0 5 8.5 9 8.5 9s8.5-4 8.5-9V6L12 3Z', 'm8 12 2.5 2.5L16 9'],
  chart: ['M4 3v17h17', 'm7 14 4-5 4 3 5-7'],
  arrow: ['M5 12h14', 'm13 6 6 6-6 6'],
  play: ['m8 5 11 7-11 7V5Z'],
  stop: ['M6 6h12v12H6z'],
  download: ['M12 3v12', 'm7 10 5 5 5-5', 'M4 16v5h16v-5'],
  refresh: ['M20 7v5h-5', 'M4 17v-5h5', 'M6.1 7a7 7 0 0 1 11.6-2L20 8', 'M4 16l2.3 3A7 7 0 0 0 18 17'],
  check: ['m5 12 4 4L19 6'],
  database: ['M4 6c0-4 16-4 16 0s-16 4-16 0Z', 'M4 6v12c0 4 16 4 16 0V6', 'M4 12c0 4 16 4 16 0'],
  info: ['M12 8h.01', 'M12 11v6', 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z'],
  alert: ['m12 3 10 18H2L12 3Z', 'M12 9v5', 'M12 17h.01'],
  lock: ['M5 10h14v11H5z', 'M8 10V6a4 4 0 0 1 8 0v4', 'M12 14v3'],
  clock: ['M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z', 'M12 7v5l3 2'],
  file: ['M14 2H5v20h14V7l-5-5Z', 'M14 2v6h5', 'M8 12h8', 'M8 16h6'],
  signal: ['M4 19v-3', 'M9 19v-7', 'M14 19V8', 'M19 19V4'],
  globe: ['M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z', 'M3 12h18', 'M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z'],
  chevron: ['m9 5 7 7-7 7'],
  flask: ['M9 3h6', 'M10 3v7l-6 9a1 1 0 0 0 1 2h14a1 1 0 0 0 1-2l-6-9V3', 'M7 15h10'],
  bolt: ['m13 2-9 12h7l-1 8 9-12h-7l1-8Z'],
  plus: ['M12 5v14', 'M5 12h14'],
  trash: ['M4 7h16', 'M9 7V4h6v3', 'M6 7l1 14h10l1-14', 'M10 11v6', 'M14 11v6'],
  eye: ['M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7Z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z'],
  target: ['M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z', 'M17 12a5 5 0 1 1-10 0 5 5 0 0 1 10 0Z', 'M13 12a1 1 0 1 1-2 0 1 1 0 0 1 2 0Z'],
  key: ['M15 7a4 4 0 1 1-3.4 6L9 15.6 6.5 13 9 10.5l3.6 3.6A4 4 0 0 1 15 7Z', 'M17.5 7h.01'],
  layers: ['m12 2 9 5-9 5-9-5 9-5Z', 'm3 12 9 5 9-5', 'm3 17 9 5 9-5'],
  activity: ['M22 12h-4l-3 8-4-16-3 8H2'],
  sliders: ['M4 6h10', 'M18 6h2', 'M4 12h4', 'M12 12h8', 'M4 18h12', 'M20 18h0', 'M14 4v4', 'M8 10v4', 'M16 16v4'],
  home: ['m3 10 9-7 9 7v10H3V10Z', 'M9 20v-6h6v6'],
  external: ['M14 4h6v6', 'M20 4 10 14', 'M18 14v5H5V6h5'],
  filter: ['M3 5h18l-7 8v6l-4 2v-8L3 5Z'],
  dot: ['M12 12h.01'],
  user: ['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z', 'M4 21a8 8 0 0 1 16 0'],
  book: ['M4 4h7v16H4z', 'M13 4h7v16h-7z'],
  terminal: ['m5 8 3 4-3 4', 'M12 16h7', 'M3 4h18v16H3z'],
}
</script>

<template>
  <svg
    :width="size" :height="size" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"
  >
    <path v-for="(path, index) in (paths[name] || paths.grid)" :key="index" :d="path" />
  </svg>
</template>
