
























































































    delete: { title: 'Test Page', reason: 'test delete' },
    protect: { title: 'Test Page', protections: [{ type: 'edit', level: 'sysop' }], reason: 'test protect' },
    purge: { titles: ['Test Page'] },
    'send-email': { username: 'TestUser', subject: 'Hi', text: 'Body' },
    upload: { filename: 'Test.png', content: Buffer.from('fake png').toString('base64'), comment: 'test upload' },
    'upload-by-url': { filename: 'Test.png', url: 'https://example.com/Test.png' },
    'add-flow-topic': { title: 'Talk:Test Page', subject: 'Hello', content: 'World' },
    'create-account': { username: 'NewUser', password: 'secret123' },
    block: { username: 'Vandal', reason: 'test block' },
    unblock: { username: 'Vandal', reason: 'test unblock' },
    undelete: { title: 'Test Page', reason: 'test undelete' },
};
