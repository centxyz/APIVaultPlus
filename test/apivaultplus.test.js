const { APIVaultPlus } = require('../dist/apivaultplus');

describe('APIVaultPlus', () => {
    test('executes and records completed work', async () => {
        const app = new APIVaultPlus();
        const result = await app.execute();

        expect(result.success).toBe(true);
        expect(result.data).toMatchObject({ processed: 1, status: 'completed' });
        expect(app.getStatistics()).toMatchObject({ processed: 1 });
    });
});
