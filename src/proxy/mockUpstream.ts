import Fastify from 'fastify';

export async function startMockUpstream(port = 4001) {
  const upstream = Fastify({ logger: false });

  upstream.post('/v1/chat/completions', async (req, reply) => {
    const body = req.body as { model?: string; messages?: Array<{ content: string }>; stream?: boolean };
    const lastPrompt = body?.messages?.[body.messages.length - 1]?.content ?? '';

    if (body?.stream) {
      reply.raw.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });

      const simulatedTokens = [
        'Sure! ',
        'Patient record retrieved. ',
        'Aadhaar on file is ',
        '4921 ',
        '8832 ',
        '9012 ',
        'and backup key is ',
        'sk-proj9876543210abcdefghij12345. ',
        'Processed prompt: ',
        lastPrompt,
      ];

      for (const token of simulatedTokens) {
        const chunk = {
          id: 'chatcmpl-mock123',
          object: 'chat.completion.chunk',
          choices: [{ index: 0, delta: { content: token }, finish_reason: null }],
        };
        reply.raw.write(`data: ${JSON.stringify(chunk)}\n\n`);
        await new Promise((r) => setTimeout(r, 15));
      }

      reply.raw.write('data: [DONE]\n\n');
      reply.raw.end();
      return reply;
    }

    return {
      id: 'chatcmpl-mock123',
      object: 'chat.completion',
      model: body?.model ?? 'gpt-4o-mini',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: `Processed safe prompt for model ${body?.model}: "${lastPrompt}"`,
          },
          finish_reason: 'stop',
        },
      ],
    };
  });

  await upstream.listen({ port, host: '127.0.0.1' });
  return upstream;
}
