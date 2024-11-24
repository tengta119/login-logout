<script setup>

</script>

<template>
  <div style="width: 100vw; height: 100vh; overflow: hidden; display: flex">
    <div style="flex: 1; background-color: black">
      <el-image fit="cover" src="https://cube.elemecdn.com/6/94/4d3ea53c084bad6931a56d5158a48jpeg.jpeg" style="width: 100%; height: 100%"></el-image>
    </div>
    <div class="welcome-title">
      <h1>Welcome to my app</h1>
    </div>

    <div class="right-card">
      <router-view/>
    </div>
  </div>
</template>

<style scoped>

.welcome-title {
  position: absolute;
  bottom: 10px;
  left: 25px;
  color: white;
  text-shadow: 0 0 10px black;
}

.right-card {
  width: 400px;
  z-index: 1;
  background-color: white;
}

</style>