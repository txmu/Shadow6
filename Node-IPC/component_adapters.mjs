/** Small, read-only IPC contracts for long-running Shadow6 components. */
const COMPONENTS = Object.freeze({
  'virtual-broker': {
    methods: ['virtual-broker.capabilities', 'virtual-broker.status', 'virtual-broker.metrics', 'virtual-broker.routes.summary', 'virtual-broker.sessions.summary'],
    schema: 'shadow6.virtual-broker-ipc.v1',
    description: 'configuration and admission runtime observability; no control mutations',
  },
  detector: {
    methods: ['detector.capabilities', 'detector.status', 'detector.metrics', 'detector.alerts.snapshot'],
    schema: 'shadow6.detector-ipc.v1',
    description: 'bounded detector health and capability observability; no packet feed over IPC',
  },
  s6na: {
    methods: ['s6na.capabilities', 's6na.status', 's6na.metrics', 's6na.sessions.summary'],
    schema: 'shadow6.s6na-ipc.v1',
    description: 'adapter profile and limit observability; transport remains separately authenticated',
  },
  'app-flow': {
    methods: ['app-flow.capabilities', 'app-flow.status', 'app-flow.metrics', 'app-flow.queue.summary'],
    schema: 'shadow6.app-flow-ipc.v1',
    description: 'bounded loopback application ingress shim; client-only and read-only over IPC',
  },
  'capsule-observer': {
    methods: ['capsule-observer.capabilities', 'capsule-observer.status', 'capsule-observer.metrics', 'capsule-observer.sessions.summary'],
    schema: 'shadow6.capability-capsule-observer-ipc.v1',
    description: 'read-only view of Control Center managed capability capsules; lifecycle control uses capsule.* methods',
  },
  plugins: { methods: ['plugins.capabilities','plugins.status','plugins.metrics','plugins.catalog'], schema: 'shadow6.plugins-ipc.v1', description: 'signed isolated plugin inventory observations' },
  slots: { methods: ['slots.capabilities','slots.status','slots.metrics','slots.catalog'], schema: 'shadow6.slots-ipc.v1', description: 'typed slot catalog observations without invocation' },
  gate: { methods: ['gate.capabilities','gate.status','gate.metrics','gate.sessions.summary'], schema: 'shadow6.gate-ipc.v1', description: 'authenticated Gate runtime observations without enablement or mutation' },
  abi: { methods: ['abi.capabilities','abi.status','abi.metrics','abi.catalog'], schema: 'shadow6.abi-ipc.v1', description: 'Core-Blind S6ABI/1 and deployment contract observations; no Core execution or mutation' },
});

export function componentCatalog(component) {
  const contract = COMPONENTS[component];
  if (!contract) throw Error('unsupported IPC component');
  return {schema: contract.schema, component, methods: contract.methods,
    read_only: true, description: contract.description};
}

export function componentHandler(component) {
  const contract = COMPONENTS[component];
  if (!contract) throw Error('unsupported IPC component');
  return (method, params) => {
    if (!params || Array.isArray(params) || typeof params !== 'object' || Object.keys(params).length) {
      throw Error('component status methods take no parameters');
    }
    if (method === `${component}.capabilities`) return componentCatalog(component);
    if (method === `${component}.status`) return {
      schema: `${contract.schema.replace('-ipc.v1', '-status.v1')}`,
      component, state: 'available', read_only: true,
      methods: contract.methods,
    };
    if (method === `${component}.metrics`) return {
      schema: `${contract.schema.replace('-ipc.v1', '-metrics.v1')}`,
      component, read_only: true, counters: {}, limits: {}, source: 'local-contract',
    };
    if (method.endsWith('.summary') || method.endsWith('.snapshot') || method.endsWith('.catalog')) return {
      schema: `${contract.schema.replace('-ipc.v1', '-observation.v1')}`,
      component, read_only: true, items: [], truncated: false, source: 'local-contract',
    };
    throw Error('unknown component method');
  };
}

export const IPC_COMPONENTS = Object.freeze(Object.keys(COMPONENTS));

export function capsuleObserverHandler(control) {
  if (typeof control !== 'function') throw Error('Control Center capsule observer binding required');
  const component = 'capsule-observer', contract = COMPONENTS[component];
  return async (method, params) => {
    if (!params || Array.isArray(params) || typeof params !== 'object' || Object.keys(params).length) {
      throw Error('capsule observer methods take no parameters');
    }
    if (method === `${component}.capabilities`) return componentCatalog(component);
    if (![`${component}.status`, `${component}.metrics`, `${component}.sessions.summary`].includes(method)) {
      throw Error('unknown component method');
    }
    const catalog = await control('capsule.list', {});
    if (!catalog || catalog.schema !== 'shadow6.capability-capsule-catalog.v1' ||
        !Array.isArray(catalog.capsules) || catalog.capsules.length > 256) {
      throw Error('invalid Control Center capsule catalog');
    }
    if (method === `${component}.sessions.summary`) {
      return {schema: 'shadow6.capability-capsule-observation.v1', component,
        read_only: true, items: catalog.capsules, truncated: false, source: 'control-center'};
    }
    if (method === `${component}.metrics`) {
      return {schema: 'shadow6.capability-capsule-metrics.v1', component, read_only: true,
        counters: {active: catalog.capsules.length,
          paused: catalog.capsules.filter(item => item.state === 'paused').length},
        limits: {capsules: 256}, source: 'control-center'};
    }
    return {schema: 'shadow6.capability-capsule-observer-status.v1', component,
      state: 'available', read_only: true, methods: contract.methods,
      active: catalog.capsules.length, source: 'control-center'};
  };
}
