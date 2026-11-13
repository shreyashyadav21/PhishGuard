import React, { useState, useEffect } from 'react';
import {
  GraduationCap,
  ShieldCheck,
  HelpCircle,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RotateCcw,
  BookOpen,
  ChevronDown,
  ChevronUp,
  Award,
  Sparkles,
  ExternalLink,
  Lock,
  Globe,
  Mail,
  Key
} from 'lucide-react';
import confetti from 'canvas-confetti';
import api from '../api/client';
import toast from 'react-hot-toast';

export default function LearnCybersecurity() {
  const [activeTab, setActiveTab] = useState('topics'); // 'topics' or 'quiz'
  const [expandedTopic, setExpandedTopic] = useState(null);

  // Quiz state
  const [questions, setQuestions] = useState([]);
  const [answers, setAnswers] = useState({});
  const [quizSubmitted, setQuizSubmitted] = useState(false);
  const [quizResult, setQuizResult] = useState(null);
  const [loadingQuiz, setLoadingQuiz] = useState(false);
  const [submittingQuiz, setSubmittingQuiz] = useState(false);

  const topics = [
    {
      id: 1,
      title: '1. What is Phishing?',
      icon: Mail,
      summary: 'A deceptive social engineering attack designed to steal passwords and personal secrets.',
      content: `Phishing is a form of cybercrime where targets are contacted by email, telephone, or text message by someone posing as a legitimate institution to lure individuals into providing sensitive data such as personally identifiable information, banking and credit card details, and passwords.\n\nThe attack relies heavily on human psychology rather than technical flaws, leveraging trust, fear, curiosity, or greed.`
    },
    {
      id: 2,
      title: '2. How Fake Websites Work',
      icon: Globe,
      summary: 'Pixel-perfect clones that harvest credentials into attacker-controlled databases.',
      content: `Attackers copy the HTML, CSS, and imagery of authentic login portals (like Microsoft 365, Google, or banking portals) and host them on spoofed domains.\n\nWhen an unsuspecting victim enters their username and password, the page submits the credentials directly to an attacker's database before redirecting the victim to the genuine site, often leaving them unaware that an intrusion occurred.`
    },
    {
      id: 3,
      title: '3. How Email Spoofing Works',
      icon: Mail,
      summary: 'Exploiting legacy SMTP protocols that lack built-in sender verification.',
      content: `The original Simple Mail Transfer Protocol (SMTP) had no mechanism to verify the sender address. Attackers can forge the "From" header to display any address they desire unless strict domain protections like SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication) are enforced.`
    },
    {
      id: 4,
      title: '4. What is Domain Impersonation?',
      icon: AlertTriangle,
      summary: 'Typosquatting, homoglyphs, and subdomains designed to fool the human eye.',
      content: `Attackers register domains that look nearly identical to popular brands. Common techniques include:\n• Typosquatting: 'amzon.com' instead of 'amazon.com'\n• Homoglyphs / Combosquatting: replacing letter 'l' with numeral '1' (e.g. 'paypa1.com') or 'rn' for 'm'\n• Deceptive Subdomains: 'paypal.com.verify-billing.xyz' where the root domain is actually 'verify-billing.xyz'`
    },
    {
      id: 5,
      title: '5. What is HTTPS?',
      icon: Lock,
      summary: 'Encryption in transit that protects against eavesdroppers, but NOT proof of legitimacy.',
      content: `HTTPS (Hypertext Transfer Protocol Secure) encrypts data between your browser and the website server using TLS. It prevents eavesdropping on open Wi-Fi.\n\nCRITICAL MISCONCEPTION: HTTPS does NOT mean the site is benign! Attackers obtain free SSL/TLS certificates for their phishing domains. Always check the actual domain name, not just the padlock icon.`
    },
    {
      id: 6,
      title: '6. What is Social Engineering?',
      icon: HelpCircle,
      summary: 'Manipulating human cognitive biases and emotional impulses to bypass technical defenses.',
      content: `Social engineering is the psychological manipulation of people into performing actions or divulging confidential information. The most common levers attackers pull are:\n• High-Pressure Urgency ('Your account will be closed in 24 hours')\n• Fear of Penalties ('Tax audit warrant issued')\n• Authority ('Request from the Chief Executive Officer')\n• Greed / Rewards ('You won $1,000,000 in the international sweepstakes')`
    },
    {
      id: 7,
      title: '7. How to Recognize Suspicious Links',
      icon: Globe,
      summary: 'Inspecting anchor targets, checking the registered root domain, and spotting tricks.',
      content: `Before clicking any link:\n1. Hover over the link to preview the actual destination URL in the browser status bar.\n2. Look at the root domain directly before the first single forward slash '/'. Everything before that defines the host.\n3. Watch for '@' symbols: in 'http://google.com@evil.com', the browser connects to 'evil.com', ignoring 'google.com' entirely.`
    },
    {
      id: 8,
      title: '8. What to Do After Clicking a Suspicious Link',
      icon: ShieldCheck,
      summary: 'Immediate damage mitigation protocol for suspected compromised credentials.',
      content: `If you entered passwords on a suspected phishing site:\n1. Immediately navigate to the legitimate official service using a known bookmark and change your password.\n2. Terminate all active sessions across devices in your account security dashboard.\n3. Enable Multi-Factor Authentication (MFA).\n4. Notify your corporate security operations (SOC) team or IT helpdesk immediately.\n5. Monitor bank transactions and credit statements for unauthorized activity.`
    },
    {
      id: 9,
      title: '9. How to Secure Online Accounts',
      icon: Key,
      summary: 'Password managers, unique credentials, and proactive exposure monitoring.',
      content: `Best practices for personal and organizational defense:\n• Use a dedicated password manager to generate and store 16+ character complex, random passwords.\n• Never reuse passwords across accounts (a breach of one site compromises all).\n• Monitor breach notification services (like HaveIBeenPwned).\n• Keep operating systems and web browsers updated to receive security patches.`
    },
    {
      id: 10,
      title: '10. How Multi-Factor Authentication (MFA) Helps',
      icon: ShieldCheck,
      summary: 'The single most effective barrier against stolen password abuse.',
      content: `Multi-Factor Authentication requires two or more verification methods:\n1. Something you know (password / PIN)\n2. Something you have (authenticator app, FIDO2 hardware security key, push notification)\n3. Something you are (biometric fingerprint / facial scan)\n\nEven if an attacker captures your password via phishing, they cannot breach your account without your secondary physical verification factor.`
    }
  ];

  const fetchQuestions = async () => {
    setLoadingQuiz(true);
    try {
      const res = await api.get('/quiz/questions');
      setQuestions(res.data.questions || []);
    } catch (err) {
      toast.error('Failed to load quiz questions');
    } finally {
      setLoadingQuiz(false);
    }
  };

  useEffect(() => {
    fetchQuestions();
  }, []);

  const handleSelectOption = (questionId, optionIndex) => {
    if (quizSubmitted) return;
    setAnswers((prev) => ({
      ...prev,
      [questionId]: optionIndex
    }));
  };

  const handleQuizSubmit = async () => {
    const answeredCount = Object.keys(answers).length;
    if (answeredCount < questions.length) {
      toast.error(`Please answer all ${questions.length} questions before submitting (${answeredCount}/${questions.length} completed)`);
      return;
    }

    setSubmittingQuiz(true);
    try {
      const res = await api.post('/quiz/submit', { answers });
      setQuizResult(res.data);
      setQuizSubmitted(true);

      if (res.data.score_percentage >= 70) {
        confetti({
          particleCount: 100,
          spread: 70,
          origin: { y: 0.6 }
        });
        toast.success(`Great job! You achieved ${res.data.score_percentage}% (${res.data.knowledge_level})`);
      } else {
        toast(`Quiz completed: ${res.data.score_percentage}%. Review the feedback to strengthen your defenses!`);
      }
    } catch (err) {
      toast.error('Failed to score quiz submission');
    } finally {
      setSubmittingQuiz(false);
    }
  };

  const handleRetryQuiz = () => {
    setAnswers({});
    setQuizSubmitted(false);
    setQuizResult(null);
  };

  return (
    <div className="space-y-6 pb-12 max-w-5xl mx-auto">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-[#00D4FF]/10 text-[#00D4FF] flex items-center justify-center border border-[#00D4FF]/20 shadow-md">
            <GraduationCap className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Cybersecurity Defense Academy</h2>
            <p className="text-xs text-[#9BAAC0]">
              Master the fundamentals of phishing detection, email authentication, and security hygiene.
            </p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex bg-[#080E19] p-1 rounded-xl border border-white/10 text-xs">
          <button
            onClick={() => setActiveTab('topics')}
            className={`px-4 py-2 rounded-lg font-bold transition-all flex items-center space-x-1.5 ${
              activeTab === 'topics'
                ? 'bg-[#00D4FF] text-[#080E19] shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Learning Modules</span>
          </button>
          <button
            onClick={() => setActiveTab('quiz')}
            className={`px-4 py-2 rounded-lg font-bold transition-all flex items-center space-x-1.5 ${
              activeTab === 'quiz'
                ? 'bg-[#00D4FF] text-[#080E19] shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Award className="w-3.5 h-3.5" />
            <span>Interactive Quiz</span>
          </button>
        </div>
      </div>

      {/* View A: 10 Learning Topics */}
      {activeTab === 'topics' && (
        <div className="space-y-4">
          <div className="soc-card p-4 flex items-center justify-between text-xs text-slate-300">
            <span>Essential Knowledge Cards (10 Core Topics)</span>
            <span className="text-cyan-400 font-semibold">Click to expand details</span>
          </div>

          <div className="space-y-3">
            {topics.map((t) => {
              const Icon = t.icon;
              const isExpanded = expandedTopic === t.id;
              return (
                <div
                  key={t.id}
                  className="soc-card overflow-hidden transition-all duration-200"
                >
                  <button
                    onClick={() => setExpandedTopic(isExpanded ? null : t.id)}
                    className="w-full p-5 text-left flex items-center justify-between hover:bg-white/[0.02] transition-colors"
                  >
                    <div className="flex items-center space-x-4">
                      <div className="w-9 h-9 rounded-xl bg-cyan-500/10 text-[#00D4FF] flex items-center justify-center shrink-0">
                        <Icon className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-white">{t.title}</h3>
                        <p className="text-xs text-slate-400 mt-0.5">{t.summary}</p>
                      </div>
                    </div>
                    {isExpanded ? (
                      <ChevronUp className="w-5 h-5 text-cyan-400 shrink-0" />
                    ) : (
                      <ChevronDown className="w-5 h-5 text-slate-500 shrink-0" />
                    )}
                  </button>

                  {isExpanded && (
                    <div className="px-5 pb-5 pt-2 border-t border-white/5 bg-[#080E19]/60">
                      <div className="whitespace-pre-line text-xs text-slate-300 leading-relaxed font-sans">
                        {t.content}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* View B: Interactive 10-Question Awareness Quiz */}
      {activeTab === 'quiz' && (
        <div className="space-y-6">
          {/* Quiz Result Banner if Submitted */}
          {quizSubmitted && quizResult && (
            <div className="soc-card p-6 bg-gradient-to-r from-[#101A2B] to-[#142238] border-[#00D4FF]/40 space-y-4">
              <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="flex items-center space-x-4">
                  <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 text-cyan-300 flex items-center justify-center text-2xl font-black border border-cyan-500/30">
                    {quizResult.score_percentage}%
                  </div>
                  <div>
                    <span className="text-xs font-bold uppercase text-slate-400 tracking-wider">
                      Assessment Result
                    </span>
                    <h3 className="text-xl font-extrabold text-white flex items-center gap-2">
                      {quizResult.knowledge_level}
                      <Award className="w-5 h-5 text-[#00D4FF]" />
                    </h3>
                    <p className="text-xs text-slate-300">
                      You answered <strong>{quizResult.correct_answers}</strong> out of{' '}
                      <strong>{quizResult.total_questions}</strong> questions correctly.
                    </p>
                  </div>
                </div>

                <button
                  onClick={handleRetryQuiz}
                  className="flex items-center space-x-2 px-5 py-2.5 bg-[#00D4FF] text-[#080E19] font-bold text-xs rounded-xl hover:bg-[#00E6A0] transition-all shadow-md shadow-[#00D4FF]/20"
                >
                  <RotateCcw className="w-4 h-4" />
                  <span>Retry Quiz</span>
                </button>
              </div>
            </div>
          )}

          {/* Question List */}
          <div className="space-y-4">
            {questions.map((q, idx) => {
              const selectedOption = answers[q.id];
              const feedback = quizResult?.feedback?.find((f) => f.question_id === q.id);

              return (
                <div key={q.id} className="soc-card p-5 space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <span className="text-xs font-bold text-cyan-400">
                      Question {idx + 1} of {questions.length}
                    </span>
                    {feedback && (
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          feedback.is_correct
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        }`}
                      >
                        {feedback.is_correct ? 'Correct' : 'Incorrect'}
                      </span>
                    )}
                  </div>

                  <h3 className="text-sm font-bold text-white leading-snug">{q.question}</h3>

                  <div className="space-y-2 pt-1">
                    {q.options.map((opt, optIdx) => {
                      const isSelected = selectedOption === optIdx;
                      let optionStyle = 'bg-[#080E19] border-white/5 text-slate-300 hover:border-cyan-500/30';

                      if (isSelected) {
                        optionStyle = 'bg-cyan-500/10 border-[#00D4FF] text-cyan-300 font-semibold';
                      }

                      if (feedback) {
                        if (optIdx === feedback.correct_index) {
                          optionStyle = 'bg-emerald-500/15 border-emerald-500/60 text-emerald-300 font-bold';
                        } else if (isSelected && !feedback.is_correct) {
                          optionStyle = 'bg-rose-500/15 border-rose-500/60 text-rose-300 line-through';
                        } else {
                          optionStyle = 'opacity-50 border-transparent text-slate-500';
                        }
                      }

                      return (
                        <button
                          key={optIdx}
                          type="button"
                          disabled={quizSubmitted}
                          onClick={() => handleSelectOption(q.id, optIdx)}
                          className={`w-full p-3 rounded-xl border text-left text-xs transition-all flex items-center justify-between ${optionStyle}`}
                        >
                          <span className="leading-relaxed">{opt}</span>
                          <span className="w-4 h-4 rounded-full border border-white/20 shrink-0 ml-3 flex items-center justify-center text-[10px]">
                            {isSelected ? '✓' : ''}
                          </span>
                        </button>
                      );
                    })}
                  </div>

                  {/* Feedback Explanation */}
                  {feedback && (
                    <div className="pt-2 text-xs bg-[#080E19]/80 p-3 rounded-xl border border-white/5 text-slate-300 leading-relaxed">
                      <strong className="text-cyan-400 block mb-1">Defense Explanation:</strong>
                      {feedback.explanation}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Submit Action Button */}
          {!quizSubmitted && (
            <div className="flex justify-center pt-4">
              <button
                onClick={handleQuizSubmit}
                disabled={submittingQuiz || Object.keys(answers).length < questions.length}
                className="px-8 py-3 bg-[#00D4FF] text-[#080E19] font-black text-xs uppercase tracking-wider rounded-xl hover:bg-[#00E6A0] disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-lg shadow-[#00D4FF]/25 flex items-center space-x-2"
              >
                {submittingQuiz ? (
                  <>
                    <RotateCcw className="w-4 h-4 animate-spin" />
                    <span>Grading Assessment...</span>
                  </>
                ) : (
                  <>
                    <Award className="w-4 h-4" />
                    <span>
                      Submit Awareness Quiz ({Object.keys(answers).length}/{questions.length})
                    </span>
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

