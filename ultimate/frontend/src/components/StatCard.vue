<template>
  <div class="bg-bastion-800/60 border border-bastion-600/40 rounded-xl p-4 text-center transition-all hover:border-bastion-500/60">
    <div class="text-2xl font-mono font-bold mb-1" :class="colorClass">{{ displayValue }}</div>
    <div class="text-[10px] font-mono text-slate-500 uppercase tracking-widest">{{ label }}</div>
  </div>
</template>

<script setup>
import { computed, ref, watch, onMounted } from 'vue'
import anime from 'animejs'

const props = defineProps({
  label: String,
  value: { type: Number, default: 0 },
  color: { type: String, default: 'cyan' },
})

const displayValue = ref(0)

const colorClass = computed(() => ({
  'text-neon-cyan': props.color === 'cyan',
  'text-neon-green': props.color === 'green',
  'text-neon-red': props.color === 'red',
  'text-neon-yellow': props.color === 'yellow',
  'text-neon-purple': props.color === 'purple',
  'text-neon-blue': props.color === 'blue',
}))

watch(() => props.value, (newVal) => {
  anime({
    targets: { val: displayValue.value },
    val: newVal,
    duration: 600,
    easing: 'easeOutExpo',
    round: 1,
    update: (anim) => { displayValue.value = anim.animations[0].currentValue },
  })
})

onMounted(() => { displayValue.value = props.value })
</script>
