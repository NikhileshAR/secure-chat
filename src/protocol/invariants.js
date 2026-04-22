function assertInvariant(name, condition, context = {}) {
  if (condition) {
    return true;
  }

  const details = {
    invariant: name,
    ...(context.details && typeof context.details === 'object' ? context.details : {}),
  };

  if (typeof context.emitSecurityEvent === 'function') {
    context.emitSecurityEvent('protocol_invariant_violation', details);
  }

  if (context.securityLog && typeof context.securityLog.append === 'function') {
    context.securityLog.append('protocol_invariant_violation', details);
  }

  throw new Error(`Protocol invariant failed: ${name}`);
}

module.exports = {
  assertInvariant,
};
