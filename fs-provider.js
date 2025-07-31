let fs;
const fsReady = (async () => {
    if (typeof globalThis.Bare !== 'undefined') {
        const bareFs = await import('bare-fs');
        fs = bareFs.default || bareFs;
    } else {
        const nodeFs = await import('fs');
        fs = nodeFs.default || nodeFs;
    }
})();

export { fs, fsReady };
