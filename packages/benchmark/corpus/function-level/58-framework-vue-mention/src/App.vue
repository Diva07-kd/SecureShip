<template><div>{{ count }}</div></template>
<script>
import _ from 'lodash';
export default { data: () => ({ count: _.map([1], x => x) }) }
</script>
